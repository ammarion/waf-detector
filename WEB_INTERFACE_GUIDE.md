# 🌐 WAF Detector Web Interface Guide

## 🎨 Designer-Friendly Web Dashboard

You now have a beautiful, modern web interface for the WAF Detector! This guide covers everything you need to know about using the web dashboard as a designer and developer.

## 🚀 Quick Start

### Option 1: Using the CLI
```bash
# Start web server on default port (8080)
waf-detect --web

# Start on custom port
waf-detect --web --port 3000
```

### Option 2: Using the dedicated web server binary
```bash
# Build and run the web server
cargo run --bin web-server

# Or build first, then run
cargo build --bin web-server
./target/debug/web-server
```

### Option 3: Testing with the test script
```bash
# Run comprehensive tests
python3 test_web_server.py
```

## 🎨 Dashboard Features

### **🔍 Single URL Scanning**
- Modern, intuitive input form
- Real-time scanning with progress indicators
- Beautiful result cards with confidence scores
- Responsive design for all devices

### **📋 Batch URL Scanning**
- Scan multiple URLs at once
- Textarea input for bulk operations
- Progress tracking for batch operations
- Organized results display

### **⚡ Quick Actions**
- Pre-configured test buttons for popular sites:
  - 📺 frame.io (CloudFront detection)
  - ☁️ CloudFlare.com (CloudFlare detection)
  - 🎬 Netflix.com (general CDN detection)
- One-click testing for rapid verification

### **📊 Beautiful Results Display**
- **Visual confidence indicators** with animated progress bars
- **Color-coded detection status** (green for detected, red for not detected)
- **Detailed evidence breakdown** with expandable sections
- **Performance metrics** showing detection time
- **Professional card-based layout**

### **🧠 Virtual Adversary (VA)**
- **Consent-gated testing** with authorized target lists
- **Baseline-aware analysis** with evidence summaries
- **Explainability panel** with enforcement classification
- **Pinned probes** for export and auditing
- **Replay plan exports** (JSON/CSV) for reproducibility
- **History panel** with filters, retention, and downloads

## 🎨 Design Features

### **Modern UI/UX**
- **Gradient backgrounds** with professional color schemes
- **Glass-morphism effects** with subtle transparencies
- **Smooth animations** and transitions
- **Responsive grid layouts** that work on mobile, tablet, and desktop
- **Typography hierarchy** using system fonts for optimal readability

### **Color Scheme**
- **Primary**: Purple gradient (`#667eea` to `#764ba2`)
- **Success**: Green indicators (`#48bb78`)
- **Error**: Red indicators (`#f56565`)
- **Neutral**: Gray backgrounds (`#f7fafc`, `#e2e8f0`)
- **Text**: Dark gray for readability (`#2d3748`, `#4a5568`)

### **Interactive Elements**
- **Hover effects** on cards and buttons
- **Loading spinners** during API calls
- **Expandable evidence sections**
- **Real-time status updates**
- **Error and success messaging**

## 🔗 API Endpoints

### **Main Endpoints**

#### **POST /api/scan**
Scan a single URL for WAF/CDN detection.

**Request:**
```json
{
  "url": "https://example.com",
  "debug": true
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "url": "https://example.com",
    "detected_waf": {
      "name": "CloudFlare",
      "confidence": 0.85
    },
    "detected_cdn": {
      "name": "CloudFlare",
      "confidence": 0.85
    },
    "evidence": [...],
    "detection_time_ms": 150,
    "timestamp": "2024-01-01T12:00:00Z"
  }
}
```

#### **POST /api/batch-scan**
Scan multiple URLs in batch.

**Request:**
```json
{
  "urls": ["https://example1.com", "https://example2.com"],
  "debug": true
}
```

#### **GET /api/providers**
List all available detection providers.

#### **GET /api/status**
Get server health status.

### **Web Pages**

- **/** or **/dashboard** - Main dashboard interface
- **/api-docs** - API documentation page

### **Virtual Adversary Endpoints**
- **POST** `/api/virtual-adversary` - Run a VA scan
- **POST** `/api/virtual-adversary/start` - Start an async VA job
- **GET** `/api/virtual-adversary/status/:id` - Poll job status
- **GET** `/api/virtual-adversary/reports` - List saved VA reports
- **GET** `/api/virtual-adversary/reports/:id` - Fetch a VA report
- **GET** `/api/virtual-adversary/reports/:id/csv` - Download VA report CSV
- **GET** `/api/virtual-adversary/reports/:id/replay.json` - Download replay plan JSON
- **GET** `/api/virtual-adversary/reports/:id/replay.csv` - Download replay plan CSV
- **GET** `/api/virtual-adversary/reports.csv` - Download report summary CSV
- **POST** `/api/virtual-adversary/reports/cleanup` - Apply retention
- **POST** `/api/virtual-adversary/reports/delete-range` - Delete report range

## 📱 Responsive Design

The web interface is fully responsive and works great on:

- **📱 Mobile phones** (320px and up)
- **📱 Tablets** (768px and up)  
- **💻 Laptops** (1024px and up)
- **🖥️ Desktops** (1200px and up)

### **Mobile-First Features**
- **Touch-friendly buttons** with proper sizing
- **Optimized layouts** that stack vertically on small screens
- **Readable text** at all zoom levels
- **Fast loading** with minimal dependencies

## 🎯 Use Cases

### **For Designers**
- **Visual feedback** on WAF/CDN detection results
- **Professional presentation** of technical data
- **Screenshot-ready** interface for reports and presentations
- **Brand-consistent** color schemes and typography

### **For Developers**
- **API testing interface** for development
- **Real-time debugging** with detailed evidence
- **Batch processing** for testing multiple endpoints
- **JSON export** capabilities

### **For Security Teams**
- **Quick WAF assessment** of target domains
- **Evidence collection** for security reports
- **Confidence scoring** for risk assessment
- **Historical tracking** through the web interface

## 🚀 Performance Features

### **Client-Side**
- **Progressive enhancement** - works without JavaScript
- **Lazy loading** of non-critical resources
- **Efficient DOM manipulation** with vanilla JavaScript
- **Client-side validation** for immediate feedback

### **Server-Side**
- **Async operations** for concurrent scanning
- **Connection pooling** for HTTP requests
- **CORS support** for cross-origin requests
- **Graceful error handling** with user-friendly messages

## 🔧 Development Features

### **Built With**
- **Rust Backend**: Axum web framework for performance
- **Modern HTML/CSS**: No external dependencies
- **Vanilla JavaScript**: Clean, dependency-free frontend
- **WebAssembly Ready**: Can be compiled to WASM if needed

### **Architecture**
- **RESTful API design** following best practices
- **Stateless operations** for scalability
- **Modular component structure**
- **Error boundary handling**

## 🎨 Customization

The web interface is designed to be easily customizable:

### **CSS Variables**
```css
:root {
  --primary-color: #667eea;
  --secondary-color: #764ba2;
  --success-color: #48bb78;
  --error-color: #f56565;
  --text-color: #2d3748;
}
```

### **Component Structure**
- **Modular CSS classes** for easy theming
- **BEM naming convention** for maintainability
- **Responsive utilities** for layout control
- **Component-based JavaScript** for functionality

## 🔒 Security Features

- **Input validation** on both client and server
- **XSS prevention** with proper escaping
- **CORS configuration** for secure cross-origin requests
- **Rate limiting ready** for production deployment

## 📊 Browser Support

- **Chrome/Chromium** ✅ (recommended)
- **Firefox** ✅
- **Safari** ✅
- **Edge** ✅
- **Mobile browsers** ✅

## 🚀 Production Deployment

### **Build for Production**
```bash
cargo build --release --bin web-server
```

### **Environment Variables**
```bash
export WAF_DETECTOR_PORT=8080
export WAF_DETECTOR_HOST=0.0.0.0
```

### **Docker Ready**
The web server is containerization-ready for production deployment.

## 🎉 What's Been Accomplished

✅ **Modern Web Interface** - Beautiful, responsive dashboard  
✅ **REST API** - Complete API with all detection endpoints  
✅ **Real-time Scanning** - AJAX-powered detection with progress indicators  
✅ **Batch Processing** - Multiple URL scanning capabilities  
✅ **Professional Design** - Designer-friendly UI with modern aesthetics  
✅ **Mobile Support** - Fully responsive across all device sizes  
✅ **Interactive Features** - Expandable evidence, quick actions, real-time updates  
✅ **Documentation** - Complete API documentation built-in  
✅ **Testing Tools** - Comprehensive test script for validation  

## 🌟 Next Steps

The web interface is production-ready! You can:

1. **Start the server** with `waf-detect --web`
2. **Open your browser** to `http://localhost:8080`
3. **Test the interface** with the quick action buttons
4. **Customize the design** to match your brand
5. **Deploy to production** when ready

**Perfect for designers who want beautiful, functional web interfaces for technical tools!** 🎨✨ 
