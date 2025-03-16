import React, { useState, useRef, useEffect } from 'react';
import { 
  Mail, 
  Link, 
  Shield, 
  AlertTriangle, 
  Info, 
  FileText, 
  ArrowDown, 
  Sun, 
  Moon,
  FileSpreadsheet,
  Download,
  FileText as FileWordIcon
} from 'lucide-react';
import './styles.css';
import * as XLSX from 'xlsx';
import * as docx from 'docx';

const { Document, Paragraph, Table, TableRow, TableCell, TextRun, 
  HeadingLevel, AlignmentType, BorderStyle, WidthType, PageOrientation } = docx;

const PhishingDetector = () => {
  const [emailContent, setEmailContent] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('input');
  const [darkMode, setDarkMode] = useState(false);
  const reportRef = useRef(null);

  // Initialize dark mode based on user preference
  useEffect(() => {
    const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setDarkMode(prefersDarkMode);
  }, []);

  // Apply dark mode to body element
  useEffect(() => {
    if (darkMode) {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
  }, [darkMode]);

  // Helper: return badge class based on severity
  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'Critical':
        return 'badge-critical';
      case 'High':
        return 'badge-high';
      case 'Medium':
        return 'badge-medium';
      case 'Low':
        return 'badge-low';
      default:
        return 'badge-default';
    }
  };

  // Parse email headers from content
  const parseEmailHeaders = (content) => {
    const headers = {};
    const headerSection = content.split(/\n\s*\n/)[0];
    
    const fromMatch = headerSection.match(/From:(.+?)(?=\n[A-Za-z-]+:|$)/s);
    if (fromMatch) headers.from = fromMatch[1].trim();
    
    const replyToMatch = headerSection.match(/Reply-To:(.+?)(?=\n[A-Za-z-]+:|$)/s);
    if (replyToMatch) headers.replyTo = replyToMatch[1].trim();
    
    const receivedMatches = headerSection.matchAll(/Received:(.+?)(?=\n[A-Za-z-]+:|$)/gs);
    if (receivedMatches) {
      headers.received = [];
      for (const match of receivedMatches) {
        headers.received.push(match[1].trim());
      }
    }
    
    return headers;
  };

  // Extract URLs from email content
  const extractUrls = (content) => {
    const urlRegex = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+)/g;
    const matches = content.match(urlRegex) || [];
    return matches;
  };

  const analyzeEmail = () => {
    setLoading(true);
    setTimeout(() => {
      const analysis = performAnalysis(emailContent);
      setResults(analysis);
      setLoading(false);
      setActiveTab('results');
    }, 1200);
  };

  const performAnalysis = (content) => {
    const indicators = [];
    let riskScore = 0;
    const headers = parseEmailHeaders(content);
    
    if (headers.from && headers.replyTo && headers.from !== headers.replyTo) {
      indicators.push({
        type: "Mismatched Reply-To",
        description: `From (${headers.from}) doesn't match Reply-To (${headers.replyTo})`,
        severity: "High",
        category: "Header"
      });
      riskScore += 25;
    }
    
    if (headers.from) {
      const displayNameMatch = headers.from.match(/([^<]+)<([^>]+)>/);
      if (displayNameMatch) {
        const displayName = displayNameMatch[1].trim().toLowerCase().replace(/\s/g, '');
        const emailAddress = displayNameMatch[2].trim().toLowerCase();
        if (!emailAddress.includes(displayName)) {
          indicators.push({
            type: "Display Name Mismatch",
            description: "The sender's display name doesn't match their email address",
            severity: "Medium",
            category: "Header"
          });
          riskScore += 20;
        }
      }
    }
    
    if (headers.received && headers.received.length > 3) {
      indicators.push({
        type: "Suspicious Email Routing",
        description: "Email passed through unusually many servers",
        severity: "Medium",
        category: "Header"
      });
      riskScore += 15;
    }
    
    const suspiciousDomains = [
      'coldwellbankermoves.com', 'bankofamerica-secure.com', 'paypa1.com', 
      'microsoft-verify.com', 'google-docs.cc', 'secure-banking.co'
    ];
    
    for (const domain of suspiciousDomains) {
      if (content.includes(domain)) {
        indicators.push({
          type: "Suspicious Domain",
          description: `Email contains suspicious domain: ${domain}`,
          severity: "High",
          category: "Content"
        });
        riskScore += 25;
      }
    }
    
    const urgencyPhrases = [
      { text: 'urgent action required', weight: 20 },
      { text: 'immediate action', weight: 15 },
      { text: 'account suspended', weight: 20 },
      { text: 'verify your account', weight: 15 },
      { text: 'security alert', weight: 10 },
      { text: 'password reset', weight: 15 },
      { text: 'password expired', weight: 15 },
      { text: 'unusual activity', weight: 10 },
      { text: 'otp request', weight: 20 },
      { text: 'confirm your identity', weight: 15 },
      { text: 'limited time offer', weight: 10 }
    ];
    
    const contentLower = content.toLowerCase();
    for (const phrase of urgencyPhrases) {
      if (contentLower.includes(phrase.text)) {
        indicators.push({
          type: "Urgency Tactics",
          description: `Email contains urgency phrase: "${phrase.text}"`,
          severity: phrase.weight >= 20 ? "High" : "Medium",
          category: "Content"
        });
        riskScore += phrase.weight;
      }
    }
    
    const extractedUrls = extractUrls(content);
    for (const url of extractedUrls) {
      if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
        indicators.push({
          type: "IP-Based URL",
          description: `Suspicious IP-based URL detected: ${url}`,
          severity: "Critical",
          category: "URL"
        });
        riskScore += 30;
      }
      
      if (url.includes('%') || url.includes('bit.ly/') || 
          url.includes('tinyurl.com/') || url.includes('goo.gl/')) {
        indicators.push({
          type: "Obfuscated URL",
          description: `Potentially obfuscated URL detected: ${url}`,
          severity: "High",
          category: "URL"
        });
        riskScore += 25;
      }
      
      const trustedBrands = ['paypal', 'microsoft', 'apple', 'amazon', 'google', 'facebook', 'instagram'];
      for (const brand of trustedBrands) {
        if (url.includes(brand) && !url.includes(`${brand}.com`)) {
          indicators.push({
            type: "Brand Impersonation",
            description: `URL appears to impersonate ${brand}: ${url}`,
            severity: "Critical",
            category: "URL"
          });
          riskScore += 30;
          break;
        }
      }
    }
    
    const linkRegex = /click here|click this link|follow this link/i;
    if (linkRegex.test(content)) {
      indicators.push({
        type: "Generic Link Text",
        description: "Email contains generic 'click here' type links",
        severity: "Medium",
        category: "Content"
      });
      riskScore += 15;
    }
    
    if (content.includes('Director') || content.includes('BSocSc') || 
        content.includes('MHRM') || content.includes('HR Services')) {
      indicators.push({
        type: "Suspicious Credentials",
        description: "Email contains potentially fake credentials or titles",
        severity: "Medium",
        category: "Content"
      });
      riskScore += 15;
    }
    
    riskScore = Math.min(100, Math.max(0, riskScore));
    
    let riskLevel;
    if (riskScore >= 85) {
      riskLevel = { level: "Critical" };
    } else if (riskScore >= 70) {
      riskLevel = { level: "High" };
    } else if (riskScore >= 45) {
      riskLevel = { level: "Medium" };
    } else if (riskScore >= 20) {
      riskLevel = { level: "Low" };
    } else {
      riskLevel = { level: "Safe" };
    }
    
    return {
      riskScore,
      riskLevel,
      indicators,
      headers,
      extractedUrls
    };
  };

  // Get current timestamp for filenames
  const getTimestamp = () => {
    const now = new Date();
    return `${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2, '0')}${now.getDate().toString().padStart(2, '0')}_${now.getHours().toString().padStart(2, '0')}${now.getMinutes().toString().padStart(2, '0')}`;
  };

  // Export as text report
  const exportReport = () => {
    if (!results) return;
    
    const timestamp = getTimestamp();
    
    let report = `PHISHING EMAIL ANALYSIS REPORT\n`;
    report += `Generated: ${new Date().toLocaleString()}\n\n`;
    report += `RISK LEVEL: ${results.riskLevel.level} (Score: ${results.riskScore}/100)\n\n`;
    report += `DETECTED INDICATORS:\n`;
    
    results.indicators.forEach(indicator => {
      report += `- ${indicator.type} (${indicator.severity}): ${indicator.description}\n`;
    });
    
    report += `\nEXTRACTED URLS:\n`;
    results.extractedUrls.forEach(url => {
      report += `- ${url}\n`;
    });
    
    report += `\nEMAIL HEADERS:\n`;
    for (const [key, value] of Object.entries(results.headers)) {
      if (key === 'received') {
        report += `- Received: [${value.length} received headers]\n`;
      } else {
        report += `- ${key}: ${value}\n`;
      }
    }
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing_analysis_${timestamp}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Export as CSV/Excel
  const exportExcel = () => {
    if (!results) return;
    
    const timestamp = getTimestamp();
    
    // Create workbook
    const wb = XLSX.utils.book_new();
    
    // Create overview sheet
    const overviewData = [
      ['PHISHING EMAIL ANALYSIS REPORT'],
      [`Generated: ${new Date().toLocaleString()}`],
      [],
      ['Risk Level', results.riskLevel.level],
      ['Risk Score', `${results.riskScore}/100`],
      []
    ];
    
    const overviewWs = XLSX.utils.aoa_to_sheet(overviewData);
    XLSX.utils.book_append_sheet(wb, overviewWs, 'Overview');
    
    // Create indicators sheet
    const indicatorsHeader = [['Type', 'Severity', 'Category', 'Description']];
    const indicatorsData = results.indicators.map(indicator => [
      indicator.type,
      indicator.severity,
      indicator.category,
      indicator.description
    ]);
    
    const indicatorsWs = XLSX.utils.aoa_to_sheet([...indicatorsHeader, ...indicatorsData]);
    XLSX.utils.book_append_sheet(wb, indicatorsWs, 'Indicators');
    
    // Create URLs sheet
    const urlsHeader = [['Extracted URLs']];
    const urlsData = results.extractedUrls.map(url => [url]);
    
    const urlsWs = XLSX.utils.aoa_to_sheet([...urlsHeader, ...urlsData]);
    XLSX.utils.book_append_sheet(wb, urlsWs, 'URLs');
    
    // Create headers sheet
    const headersHeader = [['Header', 'Value']];
    const headersData = Object.entries(results.headers).map(([key, value]) => {
      if (key === 'received') {
        return [key, `${value.length} received headers found`];
      }
      return [key, value];
    });
    
    const headersWs = XLSX.utils.aoa_to_sheet([...headersHeader, ...headersData]);
    XLSX.utils.book_append_sheet(wb, headersWs, 'Headers');
    
    // Generate XLSX file
    const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'binary' });
    
    // Convert binary string to ArrayBuffer
    function s2ab(s) {
      const buf = new ArrayBuffer(s.length);
      const view = new Uint8Array(buf);
      for (let i = 0; i < s.length; i++) {
        view[i] = s.charCodeAt(i) & 0xFF;
      }
      return buf;
    }
    
    // Create Blob and download
    const blob = new Blob([s2ab(wbout)], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing_analysis_${timestamp}.xlsx`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Export as Word Document
  const exportWord = () => {
    if (!results) return;
    
    const timestamp = getTimestamp();
    
    // Helper function to create colored text based on severity
    const getSeverityColor = (severity) => {
      switch (severity) {
        case 'Critical':
          return 'FF0000'; // Red
        case 'High':
          return 'FF6600'; // Orange
        case 'Medium':
          return 'FFCC00'; // Yellow
        case 'Low':
          return '00CC00'; // Green
        default:
          return '000000'; // Black
      }
    };
    
    // Create title and header sections
    const titleParagraph = new Paragraph({
      text: 'PHISHING EMAIL ANALYSIS REPORT',
      heading: HeadingLevel.HEADING_1,
      alignment: AlignmentType.CENTER,
      thematicBreak: true,
    });
    
    const generatedDateParagraph = new Paragraph({
      children: [
        new TextRun({
          text: `Generated: ${new Date().toLocaleString()}`,
          bold: true,
        }),
      ],
    });
    
    // Create Risk Level section
    const riskLevelParagraph = new Paragraph({
      children: [
        new TextRun({ text: 'RISK LEVEL: ', bold: true }),
        new TextRun({
          text: `${results.riskLevel.level}`,
          bold: true,
          color: getSeverityColor(results.riskLevel.level),
        }),
        new TextRun({ text: ` (Score: ${results.riskScore}/100)` }),
      ],
      spacing: { after: 200 },
    });
    
    // Create Indicators section
    const indicatorsTitleParagraph = new Paragraph({
      text: 'DETECTED INDICATORS',
      heading: HeadingLevel.HEADING_2,
      thematicBreak: true,
    });
    
    // Create indicators table
    const indicatorsTableRows = [
      new TableRow({
        children: [
          new TableCell({ 
            children: [new Paragraph({ text: 'Type', bold: true })],
            width: { size: 20, type: WidthType.PERCENTAGE },
          }),
          new TableCell({ 
            children: [new Paragraph({ text: 'Severity', bold: true })],
            width: { size: 15, type: WidthType.PERCENTAGE },
          }),
          new TableCell({ 
            children: [new Paragraph({ text: 'Category', bold: true })],
            width: { size: 15, type: WidthType.PERCENTAGE },
          }),
          new TableCell({ 
            children: [new Paragraph({ text: 'Description', bold: true })],
            width: { size: 50, type: WidthType.PERCENTAGE },
          }),
        ],
      }),
      ...results.indicators.map(indicator => 
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: indicator.type })] }),
            new TableCell({ 
              children: [
                new Paragraph({
                  children: [
                    new TextRun({
                      text: indicator.severity,
                      color: getSeverityColor(indicator.severity),
                      bold: true,
                    }),
                  ],
                }),
              ],
            }),
            new TableCell({ children: [new Paragraph({ text: indicator.category })] }),
            new TableCell({ children: [new Paragraph({ text: indicator.description })] }),
          ],
        })
      ),
    ];
    
    const indicatorsTable = new Table({
      rows: indicatorsTableRows,
      width: { size: 100, type: WidthType.PERCENTAGE },
    });
    
    // Create URLs section
    const urlsTitleParagraph = new Paragraph({
      text: 'EXTRACTED URLS',
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 400, after: 200 },
      thematicBreak: true,
    });
    
    const urlsParagraphs = results.extractedUrls.map(
      url => new Paragraph({ text: url, bullet: { level: 0 } })
    );
    
    // Create Headers section
    const headersTitleParagraph = new Paragraph({
      text: 'EMAIL HEADERS',
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 400, after: 200 },
      thematicBreak: true,
    });
    
    // Create headers table
    const headersTableRows = [
      new TableRow({
        children: [
          new TableCell({ 
            children: [new Paragraph({ text: 'Header', bold: true })],
            width: { size: 30, type: WidthType.PERCENTAGE },
          }),
          new TableCell({ 
            children: [new Paragraph({ text: 'Value', bold: true })],
            width: { size: 70, type: WidthType.PERCENTAGE },
          }),
        ],
      }),
      ...Object.entries(results.headers).map(([key, value]) => 
        new TableRow({
          children: [
            new TableCell({ 
              children: [
                new Paragraph({ 
                  text: key.charAt(0).toUpperCase() + key.slice(1),
                  bold: true,
                }),
              ],
            }),
            new TableCell({ 
              children: [
                new Paragraph({ 
                  text: key === 'received' 
                    ? `${value.length} received headers found` 
                    : value,
                }),
              ],
            }),
          ],
        })
      ),
    ];
    
    const headersTable = new Table({
      rows: headersTableRows,
      width: { size: 100, type: WidthType.PERCENTAGE },
    });
    
    // Create footer
    const footerParagraph = new Paragraph({
      children: [
        new TextRun({
          text: 'CAUTION: ',
          bold: true,
          color: 'FF0000',
        }),
        new TextRun({
          text: 'Always exercise caution with suspicious emails. Do not click links or download attachments unless you\'re certain they\'re safe.',
        }),
      ],
      spacing: { before: 400 },
      border: {
        top: { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' },
        bottom: { style: BorderStyle.NONE },
        left: { style: BorderStyle.NONE },
        right: { style: BorderStyle.NONE },
      },
      spacing: { before: 400 },
    });
    
    // Build document
    const doc = new Document({
      sections: [
        {
          properties: {
            page: {
              margin: {
                top: 1000,
                right: 1000,
                bottom: 1000,
                left: 1000,
              },
            },
          },
          children: [
            titleParagraph,
            generatedDateParagraph,
            riskLevelParagraph,
            indicatorsTitleParagraph,
            ...(results.indicators.length > 0 
              ? [indicatorsTable] 
              : [new Paragraph({ text: 'No phishing indicators detected. This email appears safe.' })]),
            urlsTitleParagraph,
            ...(results.extractedUrls.length > 0 
              ? urlsParagraphs 
              : [new Paragraph({ text: 'No URLs detected in the email.' })]),
            headersTitleParagraph,
            headersTable,
            footerParagraph,
          ],
        },
      ],
    });
    
    // Generate Word document
    docx.Packer.toBlob(doc).then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishing_analysis_${timestamp}.docx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  };

  const getCategoryIcon = (category) => {
    switch(category) {
      case 'Header':
        return <Mail className="icon" />;
      case 'URL':
        return <Link className="icon" />;
      case 'Content':
        return <FileText className="icon" />;
      default:
        return <Info className="icon" />;
    }
  };

  // Toggle dark mode
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  return (
    <div className={`container ${darkMode ? 'dark-theme' : 'light-theme'}`}>
      <div className="header">
        <h1 className="title">Phishing Email Detector</h1>
        <p className="subtitle">Analyze emails for phishing indicators, headers and suspicious URLs</p>
        
        {/* Dark Mode Toggle */}
        <button
          className="dark-mode-toggle"
          onClick={toggleDarkMode}
          title={darkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
        >
          {darkMode ? 
            <Sun className="dark-mode-icon" /> : 
            <Moon className="dark-mode-icon" />
          }
        </button>
      </div>
      
      <div className="card">
        <div className="tab-header">
          <button 
            className={`tab-button ${activeTab === 'input' ? 'active' : 'inactive'}`}
            onClick={() => setActiveTab('input')}
          >
            <Mail className="tab-icon" />
            Email Input
          </button>
          {results && (
            <button 
              className={`tab-button ${activeTab === 'results' ? 'active' : 'inactive'}`}
              onClick={() => setActiveTab('results')}
            >
              <Shield className="tab-icon" />
              Analysis Results
            </button>
          )}
        </div>
        
        {activeTab === 'input' && (
          <div className="tab-content">
            <textarea
              className="email-textarea"
              placeholder="Paste full email content here including headers (From:, Reply-To:, etc.)"
              value={emailContent}
              onChange={(e) => setEmailContent(e.target.value)}
            ></textarea>
            <div className="button-group">
              <button 
                className="analyze-button"
                onClick={analyzeEmail}
                disabled={!emailContent.trim() || loading}
              >
                {loading ? (
                  <span className="loading">
                    <svg className="spinner" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="spinner-path" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="spinner-tail" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Analyzing...
                  </span>
                ) : (
                  <span className="button-content">
                    <Shield className="button-icon" />
                    Analyze Email
                  </span>
                )}
              </button>
            </div>
          </div>
        )}
        
        {activeTab === 'results' && results && (
          <div className="tab-content" ref={reportRef}>
            <div className="results-header">
              <h2 className="results-title">Analysis Results</h2>
              <div className="results-actions">
                <button 
                  className="export-button"
                  onClick={exportReport}
                  title="Export as text file (.txt)"
                >
                  <Download className="export-icon" />
                  Text
                </button>
                <button 
                  className="export-button export-excel"
                  onClick={exportExcel}
                  title="Export as Excel file (.xlsx)"
                  style={{ backgroundColor: '#217346', color: 'white' }}
                >
                  <FileSpreadsheet className="export-icon" />
                  Excel
                </button>
                <button 
                  className="export-button export-word"
                  onClick={exportWord}
                  title="Export as Word file (.docx)"
                  style={{ backgroundColor: '#2B579A', color: 'white' }}
                >
                  <FileWordIcon className="export-icon" />
                  Word
                </button>
              </div>
            </div>
            
            <div className={`risk-level ${results.riskLevel.level.toLowerCase()}`}>
              <div className="risk-info">
                <div className="risk-title">{results.riskLevel.level} Risk</div>
                <div className="risk-subtitle">
                  This email shows {results.indicators.length} indicator{results.indicators.length !== 1 ? 's' : ''} of phishing
                </div>
              </div>
              <div className="risk-meter">
                <div 
                  className="risk-meter-fill" 
                  style={{ width: `${results.riskScore}%` }}
                ></div>
              </div>
              <div className="risk-score">{results.riskScore}/100</div>
            </div>
            
            {results.indicators.length > 0 ? (
              <div className="section">
                <h3 className="section-heading">Detected Indicators</h3>
                <div className="indicators-list">
                  {results.indicators.map((indicator, index) => (
                    <div key={index} className="indicator-item">
                      <div className="indicator-row">
                        <div className="indicator-details">
                          <div className="indicator-icon">
                            {getCategoryIcon(indicator.category)}
                          </div>
                          <div className="indicator-text">
                            <div className="indicator-title">{indicator.type}</div>
                            <div className="indicator-description">{indicator.description}</div>
                          </div>
                        </div>
                        <div className={`badge ${getSeverityBadge(indicator.severity)}`}>
                          {indicator.severity}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="safe-message">
                No phishing indicators detected. This email appears safe.
              </div>
            )}
            
            {results.extractedUrls.length > 0 && (
              <div className="section">
                <h3 className="section-heading">Extracted URLs</h3>
                <div className="url-container">
                  <ul className="url-list">
                    {results.extractedUrls.map((url, index) => (
                      <li key={index} className="url-item">
                        <Link className="url-icon" />
                        <div className="url-text">{url}</div>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
            
            <div className="section">
              <h3 className="section-heading">Header Analysis</h3>
              <div className="header-container">
                <div className="header-list">
                  {Object.entries(results.headers).map(([key, value]) => (
                    <div key={key} className="header-detail">
                      <span className="header-key">
                        {key.charAt(0).toUpperCase() + key.slice(1)}:
                      </span>
                      {key === 'received' ? (
                        <span className="header-value"> {value.length} received headers found</span>
                      ) : (
                        <span className="header-value"> {value}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
            
            <div className="footer">
              <div className="footer-content">
                <AlertTriangle className="footer-icon" />
                <p>Always exercise caution with suspicious emails. Do not click links or download attachments unless you're certain they're safe.</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PhishingDetector;