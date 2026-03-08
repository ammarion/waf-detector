use crate::active::{guard_target, ResolvedTarget};
use crate::audit::AuditSession;
use crate::effectiveness::consent::ConsentManager;
use crate::effectiveness::static_detection::analyze_static_page;
use crate::effectiveness::EffectivenessConfig;
use crate::engine::DetectionEngine;
use crate::hardening::finding::{
    CiGateMode, CoverageSummary, HardeningReport, HardeningSummary, ProviderDetectionSummary,
    RegressionPack, SurfaceAssessment, VendorMode,
};
use crate::hardening::regression::build_regression_pack;
use crate::hardening::translate::{
    surface_assessment_from_static, translate_effectiveness, translate_smoke,
    translate_surface_assessment, translate_va, translate_va2, RouteFindingContext,
    TranslationBundle,
};
use crate::hardening::vendor::{apply_vendor_guidance, resolve_vendor_mode};
use crate::payload::waf_smoke_test::{SmokeTestConfig, WafSmokeTest};
use crate::registry::ProviderRegistry;
use crate::surface::{
    LiveSurfaceVerifier, ResolvedAuthProfile, RouteAwarePlan, RouteAwarePlanner, SurfaceEndpoint,
    SurfaceMap,
};
use crate::virtual_adversary::{VirtualAdversaryConfig, VirtualAdversaryRunner};
use crate::virtual_adversary2::{build_va2_campaign_plan, Va2CampaignConfig, Va2Phase, Va2Runner};
use anyhow::Result;

pub struct HardeningExecution {
    pub report: HardeningReport,
    pub audit: Option<AuditSession>,
    pub refined_surface_map: Option<SurfaceMap>,
}

#[derive(Debug, Clone)]
pub struct HardeningConfig {
    pub ci_gate: CiGateMode,
    pub vendor_mode: VendorMode,
    pub smoke: SmokeTestConfig,
    pub va: VirtualAdversaryConfig,
    pub va2: Va2CampaignConfig,
    pub va2_phases: Vec<Va2Phase>,
    pub effectiveness: EffectivenessConfig,
    pub surface_map: Option<SurfaceMap>,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        let smoke = SmokeTestConfig {
            quiet: true,
            ..SmokeTestConfig::default()
        };
        let va = VirtualAdversaryConfig {
            tier: 2,
            ..VirtualAdversaryConfig::default()
        };
        Self {
            ci_gate: CiGateMode::Off,
            vendor_mode: VendorMode::Auto,
            smoke,
            va,
            va2: Va2CampaignConfig::default(),
            va2_phases: vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance],
            effectiveness: EffectivenessConfig::default(),
            surface_map: None,
        }
    }
}

pub struct HardeningOrchestrator {
    registry: ProviderRegistry,
    config: HardeningConfig,
}

impl HardeningOrchestrator {
    pub fn new(registry: ProviderRegistry, config: HardeningConfig) -> Self {
        Self { registry, config }
    }

    pub async fn run(&self, target_url: &str) -> Result<HardeningExecution> {
        let scope = ConsentManager::new();
        let target = guard_target(&scope, target_url)?;
        let mut audit = AuditSession::new(
            "hardening",
            &target,
            self.config.effectiveness.audit_logging,
        )?;
        let engine = DetectionEngine::new(self.registry.clone())?.with_waf_mode_detection();

        let detection = match engine.detect(&target.normalized_url).await {
            Ok(result) => result,
            Err(err) => {
                audit.record_failed(&err.to_string())?;
                return Err(err);
            }
        };

        let mut vendor_mode = resolve_vendor_mode(self.config.vendor_mode, &detection);
        let static_analysis = match analyze_static_page(&target.normalized_url).await {
            Ok(analysis) => Some(analysis),
            Err(err) => {
                tracing::warn!(
                    "hardening static assessment failed for {}: {}",
                    target.normalized_url,
                    err
                );
                None
            }
        };
        if vendor_mode == VendorMode::Auto {
            if let Some(hint) = self
                .config
                .surface_map
                .as_ref()
                .and_then(|surface_map| surface_map.vendor_hint.as_deref())
            {
                if let Ok(parsed) = VendorMode::parse(hint) {
                    vendor_mode = parsed;
                }
            }
        }

        let mut initial_surface = surface_assessment_from_static(static_analysis.as_ref(), None);
        let provider = detection
            .detected_waf
            .as_ref()
            .map(|provider| provider.name.clone())
            .or_else(|| {
                detection
                    .detected_cdn
                    .as_ref()
                    .map(|provider| provider.name.clone())
            });

        let mut refined_surface_map = None;
        let mut route_plan = None;
        if let Some(surface_map) = &self.config.surface_map {
            let verifier = LiveSurfaceVerifier::new()?;
            let refined = verifier.refine(surface_map, &target).await?;
            let auth_profile_available = ResolvedAuthProfile::from_env_path()?
                .map(|profile| !profile.is_empty())
                .unwrap_or(false);
            let planner = RouteAwarePlanner::new();
            let plan = planner.plan(&refined, auth_profile_available)?;
            if !plan.selected_routes.is_empty() {
                initial_surface.suitable = true;
                initial_surface.reason =
                    "Route-aware surface compilation identified executable input-processing endpoints."
                        .to_string();
                initial_surface.confidence = initial_surface.confidence.max(0.7);
                initial_surface.indicators.push(format!(
                    "Route-aware planner selected {} endpoints",
                    plan.selected_routes.len()
                ));
            }
            refined_surface_map = Some(refined);
            route_plan = Some(plan);
        }

        if !initial_surface.suitable && route_plan.is_none() {
            let bundle = translate_surface_assessment(&target, &initial_surface, None);
            let mut report = base_report(&target, &detection, vendor_mode, initial_surface);
            report.findings = bundle.findings;
            report.evidence_inventory = bundle.evidence_inventory;
            report.coverage = bundle.coverage;
            report.regression_pack = RegressionPack::default();
            audit.record_completed()?;
            report.audit = Some(audit.snapshot());
            report.refresh_summary(self.config.ci_gate, vendor_mode, provider, bundle.notes);
            return Ok(HardeningExecution {
                report,
                audit: Some(audit),
                refined_surface_map: None,
            });
        }

        let mut notes = Vec::new();
        let mut bundles = Vec::new();
        let surface_assessment = initial_surface.clone();

        let mut report = base_report(&target, &detection, vendor_mode, surface_assessment);
        if let Some(surface_map) = &refined_surface_map {
            report.surface_map_summary = Some(surface_map.summary.clone());
        }

        if let Some(plan) = route_plan {
            report.refined_surface_map_stats = Some(plan.stats.clone());
            notes.extend(route_plan_notes(&plan));
            if plan.selected_routes.is_empty() {
                bundles.push(translate_surface_assessment(
                    &target,
                    &report.surface_assessment,
                    None,
                ));
            } else {
                for planned_route in &plan.selected_routes {
                    self.run_route_bundle(&target, planned_route, &mut bundles, &mut notes)
                        .await;
                }
            }
        } else {
            let smoke = self.run_smoke(&target).await;
            let va = self.run_va(&target);
            let va2 = self.run_va2(&target, None).await;
            let effectiveness = self.run_effectiveness(&target).await;

            let surface_assessment = match &smoke {
                Ok(report) => {
                    surface_assessment_from_static(static_analysis.as_ref(), Some(report))
                }
                Err(_) => report.surface_assessment.clone(),
            };
            report.surface_assessment = surface_assessment.clone();
            if !surface_assessment.suitable {
                bundles.push(translate_surface_assessment(
                    &target,
                    &surface_assessment,
                    None,
                ));
            }

            match smoke {
                Ok(report) => bundles.push(translate_smoke(&target, &report, None)),
                Err(err) => notes.push(format!("Smoke phase failed: {err}")),
            }
            match va {
                Ok(report) => bundles.push(translate_va(&target, &report, None)),
                Err(err) => notes.push(format!("VA phase failed: {err}")),
            }
            match va2 {
                Ok(report) => bundles.push(translate_va2(&target, &report, None)),
                Err(err) => notes.push(format!("VA2 phase failed: {err}")),
            }
            match effectiveness {
                Ok(report) => bundles.push(translate_effectiveness(
                    &target,
                    &report,
                    self.config.effectiveness.intensity_level,
                    None,
                )),
                Err(err) => notes.push(format!("Effectiveness phase failed: {err}")),
            }
        }

        merge_bundles(&mut report, &mut notes, bundles);
        apply_vendor_guidance(&mut report.findings, vendor_mode);
        report.regression_pack =
            build_regression_pack(&mut report.findings, &report.evidence_inventory);
        audit.record_completed()?;
        report.audit = Some(audit.snapshot());
        report.refresh_summary(self.config.ci_gate, vendor_mode, provider, notes);

        Ok(HardeningExecution {
            report,
            audit: Some(audit),
            refined_surface_map,
        })
    }

    async fn run_smoke(
        &self,
        target: &ResolvedTarget,
    ) -> Result<crate::payload::waf_smoke_test::SmokeTestResult> {
        let runner = WafSmokeTest::new(self.config.smoke.clone())?;
        runner.run_test_with_target(target).await
    }

    fn run_va(&self, target: &ResolvedTarget) -> Result<crate::virtual_adversary::VaRunReport> {
        let mut runner = VirtualAdversaryRunner::new(self.config.va.clone())?;
        runner.run_with_events_for_target(target, |_, _| {}, |_| {})
    }

    async fn run_va2(
        &self,
        target: &ResolvedTarget,
        endpoint: Option<&SurfaceEndpoint>,
    ) -> Result<crate::virtual_adversary2::Va2RunReport> {
        let mut plan = build_va2_campaign_plan(
            &target.normalized_url,
            &self.config.va2_phases,
            self.config.va2,
        )?;
        if let Some(endpoint) = endpoint {
            rewrite_va2_plan_for_endpoint(&mut plan, endpoint);
        }
        let runner = Va2Runner::new()?;
        runner.run_plan_with_target(plan, target).await
    }

    async fn run_effectiveness(
        &self,
        target: &ResolvedTarget,
    ) -> Result<crate::effectiveness::report::EffectivenessReport> {
        let mut test =
            crate::effectiveness::EffectivenessTest::new(self.config.effectiveness.clone()).await?;
        test.test_effectiveness_with_target(target).await
    }

    async fn run_route_bundle(
        &self,
        base_target: &ResolvedTarget,
        planned_route: &crate::surface::PlannedRoute,
        bundles: &mut Vec<TranslationBundle>,
        notes: &mut Vec<String>,
    ) {
        let route_target = match base_target.with_url(&planned_route.execution_url) {
            Ok(target) => target,
            Err(err) => {
                notes.push(format!(
                    "Route {} could not be normalized for execution: {err}",
                    planned_route.endpoint.path_template
                ));
                return;
            }
        };
        let context = RouteFindingContext::from(&planned_route.endpoint);

        if route_target.normalized_url != base_target.normalized_url {
            notes.push(format!(
                "Route-aware hardening executing {} via {}",
                planned_route.endpoint.path_template, route_target.normalized_url
            ));
        }

        if planned_route.endpoint.supports_get_like() {
            match self.run_smoke(&route_target).await {
                Ok(report) => bundles.push(translate_smoke(&route_target, &report, Some(&context))),
                Err(err) => notes.push(format!(
                    "Smoke phase failed for {}: {err}",
                    planned_route.endpoint.path_template
                )),
            }
        } else {
            notes.push(format!(
                "Smoke phase skipped for {} because it does not expose a GET/HEAD/OPTIONS surface",
                planned_route.endpoint.path_template
            ));
        }

        match self.run_va(&route_target) {
            Ok(report) => bundles.push(translate_va(&route_target, &report, Some(&context))),
            Err(err) => notes.push(format!(
                "VA phase failed for {}: {err}",
                planned_route.endpoint.path_template
            )),
        }

        match self
            .run_va2(&route_target, Some(&planned_route.endpoint))
            .await
        {
            Ok(report) => bundles.push(translate_va2(&route_target, &report, Some(&context))),
            Err(err) => notes.push(format!(
                "VA2 phase failed for {}: {err}",
                planned_route.endpoint.path_template
            )),
        }

        match self.run_effectiveness(&route_target).await {
            Ok(report) => bundles.push(translate_effectiveness(
                &route_target,
                &report,
                self.config.effectiveness.intensity_level,
                Some(&context),
            )),
            Err(err) => notes.push(format!(
                "Effectiveness phase failed for {}: {err}",
                planned_route.endpoint.path_template
            )),
        }
    }
}

fn route_plan_notes(plan: &RouteAwarePlan) -> Vec<String> {
    let mut notes = plan
        .deferred_routes
        .iter()
        .flat_map(|route| {
            route
                .notes
                .iter()
                .map(move |note| format!("{}: {}", route.endpoint.path_template, note))
        })
        .collect::<Vec<_>>();
    notes.push(format!(
        "Route-aware planner selected {} endpoints and left {} deferred.",
        plan.selected_routes.len(),
        plan.deferred_routes.len()
    ));
    notes
}

fn rewrite_va2_plan_for_endpoint(
    plan: &mut crate::virtual_adversary2::Va2CampaignPlan,
    endpoint: &SurfaceEndpoint,
) {
    let preferred_method = preferred_endpoint_method(endpoint);
    let sample_request = endpoint.sample_request.clone();

    for step in &mut plan.steps {
        step.path = endpoint.execution_path.clone();
        if !endpoint.methods.iter().any(|method| method == &step.method) {
            step.method = preferred_method.clone();
        }

        if step.query.is_none() {
            step.query = sample_request
                .as_ref()
                .and_then(|sample| sample.query.clone());
        }

        if let Some(content_type) = sample_request
            .as_ref()
            .and_then(|sample| sample.content_type.clone())
        {
            step.headers
                .entry("Content-Type".to_string())
                .or_insert(content_type);
        }

        if step.body.is_none() && step.method != "GET" && step.method != "HEAD" {
            step.body = sample_request
                .as_ref()
                .and_then(|sample| sample.body.clone())
                .or_else(|| default_body_for_endpoint(endpoint));
        }
    }
}

fn preferred_endpoint_method(endpoint: &SurfaceEndpoint) -> String {
    endpoint
        .methods
        .iter()
        .find(|method| matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"))
        .cloned()
        .or_else(|| endpoint.methods.first().cloned())
        .unwrap_or_else(|| "GET".to_string())
}

fn default_body_for_endpoint(endpoint: &SurfaceEndpoint) -> Option<String> {
    if endpoint.parser_traits.graphql {
        return Some("{\"query\":\"query { __typename }\"}".to_string());
    }
    if endpoint.parser_traits.json {
        return Some("{\"value\":\"test\"}".to_string());
    }
    if endpoint.parser_traits.form {
        return Some("value=test".to_string());
    }
    if endpoint.parser_traits.multipart {
        return Some("--waf-detector-boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nsample\r\n--waf-detector-boundary--".to_string());
    }
    None
}

fn base_report(
    target: &ResolvedTarget,
    detection: &crate::DetectionResult,
    vendor_mode: VendorMode,
    surface_assessment: SurfaceAssessment,
) -> HardeningReport {
    HardeningReport {
        target: target.normalized_url.clone(),
        provider_detection: ProviderDetectionSummary {
            detected_waf: detection
                .detected_waf
                .as_ref()
                .map(|provider| provider.name.clone()),
            waf_confidence: detection
                .detected_waf
                .as_ref()
                .map(|provider| provider.confidence),
            detected_cdn: detection
                .detected_cdn
                .as_ref()
                .map(|provider| provider.name.clone()),
            cdn_confidence: detection
                .detected_cdn
                .as_ref()
                .map(|provider| provider.confidence),
            vendor_mode,
        },
        surface_assessment,
        surface_map_summary: None,
        refined_surface_map_stats: None,
        findings: Vec::new(),
        regression_pack: RegressionPack::default(),
        coverage: CoverageSummary::default(),
        evidence_inventory: Vec::new(),
        audit: None,
        summary: HardeningSummary {
            ci_gate: CiGateMode::Off,
            vendor_mode,
            ..HardeningSummary::default()
        },
    }
}

fn merge_bundles(
    report: &mut HardeningReport,
    notes: &mut Vec<String>,
    bundles: Vec<TranslationBundle>,
) {
    for bundle in bundles {
        for source in bundle.coverage.sources_run {
            if !report.coverage.sources_run.contains(&source) {
                report.coverage.sources_run.push(source);
            }
        }
        for (family, count) in bundle.coverage.findings_by_family {
            *report
                .coverage
                .findings_by_family
                .entry(family)
                .or_insert(0) += count;
        }
        for (channel, score) in bundle.coverage.channel_scores {
            report.coverage.channel_scores.insert(channel, score);
        }
        if bundle.coverage.coverage_score.is_some() {
            report.coverage.coverage_score = bundle.coverage.coverage_score;
        }
        notes.extend(bundle.notes);
        report.findings.extend(bundle.findings);
        report.evidence_inventory.extend(bundle.evidence_inventory);
    }
    report.coverage.evidence_count = report.evidence_inventory.len();
}
