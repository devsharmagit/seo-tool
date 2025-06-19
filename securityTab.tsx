import React, { useEffect, useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Loader2, Globe } from 'lucide-react';

// --- Types & Interfaces ---

interface SslEndpointDetails {
  protocols?: { name: string; version: string }[];
  cert?: { subject: string };
  key?: { alg: string; size: number };
  forwardSecrecy?: boolean;
}

interface SslEndpoint {
  ipAddress: string;
  grade?: string;
  details?: SslEndpointDetails;
}

interface SslData {
  endpoints?: SslEndpoint[];
  status?: string;
  [key: string]: any;
}

interface SecurityHeaders {
  strictTransportSecurity: string | null;
  xFrameOptions: string | null;
  xXssProtection: string | null;
  contentSecurityPolicy: string | null;
  xContentTypeOptions: string | null;
}

interface AdminUrlVuln {
  url: string;
  status: number;
  accessible: boolean;
}

interface SensitiveFileVuln {
  file: string;
  accessible: boolean;
  status: number;
}

interface Vulnerabilities {
  adminUrls: AdminUrlVuln[];
  directoryIndexing: boolean;
  sensitiveFiles: SensitiveFileVuln[];
}

interface SecurityStatusProps {
  status: string | null;
  label: string;
}

// --- Component ---

const SecurityTab = ({url}: {url:string}) => {

  const [loading, setLoading] = useState<boolean>(false);
  const [sslData, setSslData] = useState<SslData | null>(null);
  const [securityHeaders, setSecurityHeaders] = useState<SecurityHeaders | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerabilities | null>(null);
  const [error, setError] = useState<string>('');

  // Extract hostname from URL
  const extractHostname = (url: string): string => {
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      return urlObj.hostname;
    } catch {
      return url;
    }
  };

  // Check SSL/TLS using SSL Labs API
  const checkSSL = async (hostname: string): Promise<SslData | null> => {
    try {
      // Start new assessment
      const startResponse = await fetch(
        `https://api.ssllabs.com/api/v3/analyze?host=${hostname}&startNew=on&all=done`,
        { mode: 'cors' }
      );
      
      if (!startResponse.ok) throw new Error('SSL Labs API error');
      
      // Poll for results
      let attempts = 0;
      const maxAttempts = 30;
      
      while (attempts < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
        
        const pollResponse = await fetch(
          `https://api.ssllabs.com/api/v3/analyze?host=${hostname}&all=done`,
          { mode: 'cors' }
        );
        
        if (!pollResponse.ok) throw new Error('SSL Labs polling error');
        
        const data: SslData = await pollResponse.json();
        
        if (data.status === 'READY') {
          return data;
        } else if (data.status === 'ERROR') {
          throw new Error('SSL Labs analysis failed');
        }
        
        attempts++;
      }
      
      throw new Error('SSL analysis timeout');
    } catch (err) {
      console.error('SSL check failed:', err);
      return null;
    }
  };

  // Check security headers and vulnerabilities
  const checkSecurityHeaders = async (hostname: string): Promise<{ headers: SecurityHeaders; vulnerabilities: Vulnerabilities }> => {
    const baseUrl = `https://${hostname}`;
    const headers: SecurityHeaders = {
      strictTransportSecurity: null,
      xFrameOptions: null,
      xXssProtection: null,
      contentSecurityPolicy: null,
      xContentTypeOptions: null,
    };
    const vulns: Vulnerabilities = {
      adminUrls: [],
      directoryIndexing: false,
      sensitiveFiles: []
    };

    try {
      // Check main page headers
      const response = await fetch(baseUrl, { 
        method: 'HEAD',
        mode: 'cors',
        redirect: 'follow'
      });
      
      // Extract security headers
      headers.strictTransportSecurity = response.headers.get('strict-transport-security') || null;
      headers.xFrameOptions = response.headers.get('x-frame-options') || null;
      headers.xXssProtection = response.headers.get('x-xss-protection') || null;
      headers.contentSecurityPolicy = response.headers.get('content-security-policy') || null;
      headers.xContentTypeOptions = response.headers.get('x-content-type-options') || null;
      
    } catch (err) {
      console.error('Header check failed:', err);
    }

    // Check for common admin URLs
    const adminPaths = [
      '/admin',
      '/administrator',
      '/wp-admin',
      '/admin.php',
      '/login',
      '/dashboard',
      '/cpanel',
      '/control',
      '/manager'
    ];

    for (const path of adminPaths) {
      try {
        const adminResponse = await fetch(`${baseUrl}${path}`, { 
          method: 'HEAD',
          mode: 'cors',
          redirect: 'manual'
        });
        
        if (adminResponse.status !== 404 && adminResponse.status !== 0) {
          vulns.adminUrls.push({
            url: path,
            status: adminResponse.status,
            accessible: adminResponse.status < 400
          });
        }
      } catch (err) {
        // Ignore errors for admin URL checks
      }
    }

    // Check for directory indexing
    try {
      const dirResponse = await fetch(`${baseUrl}/`, { mode: 'cors' });
      const dirText = await dirResponse.text();
      
      if (dirText.includes('Index of /') || 
          dirText.includes('Directory Listing') ||
          dirText.includes('<title>Index of')) {
        vulns.directoryIndexing = true;
      }
    } catch (err) {
      // Ignore errors
    }

    // Check for sensitive files
    const sensitiveFiles = [
      '/.env',
      '/config.php',
      '/wp-config.php',
      '/.htaccess',
      '/robots.txt',
      '/sitemap.xml',
      '/backup.sql',
      '/database.sql',
      '/.git/config',
      '/composer.json',
      '/package.json'
    ];

    for (const file of sensitiveFiles) {
      try {
        const fileResponse = await fetch(`${baseUrl}${file}`, { 
          method: 'HEAD',
          mode: 'cors'
        });
        
        if (fileResponse.status === 200) {
          vulns.sensitiveFiles.push({
            file: file,
            accessible: true,
            status: fileResponse.status
          });
        }
      } catch (err) {
        // Ignore errors for file checks
      }
    }

    return { headers, vulnerabilities: vulns };
  };

  

  const getGradeColor = (grade: string | undefined): string => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'text-green-600';
      case 'B':
        return 'text-yellow-600';
      case 'C':
      case 'D':
        return 'text-orange-600';
      case 'F':
        return 'text-red-600';
      default:
        return 'text-gray-600';
    }
  };
useEffect(()=>{
  const analyzeWebsite = async (): Promise<void> => {
    if (!url) return;
    
    setLoading(true);
    setError('');
    setSslData(null);
    setSecurityHeaders(null);
    setVulnerabilities(null);

    try {
      const hostname = extractHostname(url);
      
      // Run SSL and security checks in parallel
      const [sslResult, securityResult] = await Promise.all([
        checkSSL(hostname),
        checkSecurityHeaders(hostname)
      ]);

      setSslData(sslResult);
      setSecurityHeaders(securityResult.headers);
      setVulnerabilities(securityResult.vulnerabilities);
      
    } catch (err) {
      setError(`Analysis failed: ${err}`);
    } finally {
      setLoading(false);
    }
  };  
  if (url) {

      analyzeWebsite();
    }
},[url])

  const SecurityStatus: React.FC<SecurityStatusProps> = ({ status, label }) => {
    const isSecure = status !== null && status !== undefined;
    return (
      <div className="flex items-center gap-2 p-2 rounded-lg bg-gray-50">
        {isSecure ? (
          <CheckCircle className="w-5 h-5 text-green-500" />
        ) : (
          <XCircle className="w-5 h-5 text-red-500" />
        )}
        <div>
          <div className="font-medium">{label}</div>
          <div className="text-sm text-gray-600">
            {isSecure ? (status && status.length > 50 ? `${status.substring(0, 50)}...` : status) : 'Not implemented'}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white">
     

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            <span className="text-red-700">{error}</span>
          </div>
        </div>
      )}

      {sslData && (
        <div className="mb-8 p-6 bg-blue-50 border border-blue-200 rounded-lg">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-600" />
            SSL/TLS Analysis
          </h2>
          
          {sslData.endpoints && sslData.endpoints.length > 0 ? (
            <div className="grid gap-4">
              {sslData.endpoints.map((endpoint, index) => (
                <div key={index} className="bg-white p-4 rounded-lg border">
                  <div className="flex items-center gap-4 mb-3">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">IP:</span>
                      <span className="font-mono text-sm bg-gray-100 px-2 py-1 rounded">
                        {endpoint.ipAddress}
                      </span>
                    </div>
                    {endpoint.grade && (
                      <div className="flex items-center gap-2">
                        <span className="font-medium">Grade:</span>
                        <span className={`text-2xl font-bold ${getGradeColor(endpoint.grade)}`}>
                          {endpoint.grade}
                        </span>
                      </div>
                    )}
                  </div>
                  
                  {endpoint.details && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="font-medium">Protocol:</span>
                        <span className="ml-2">{endpoint.details.protocols?.map(p => `${p.name} ${p.version}`).join(', ')}</span>
                      </div>
                      <div>
                        <span className="font-medium">Certificate:</span>
                        <span className="ml-2">{endpoint.details.cert?.subject}</span>
                      </div>
                      <div>
                        <span className="font-medium">Key:</span>
                        <span className="ml-2">{endpoint.details.key?.alg} {endpoint.details.key?.size} bits</span>
                      </div>
                      <div>
                        <span className="font-medium">Forward Secrecy:</span>
                        <span className="ml-2">{endpoint.details.forwardSecrecy ? 'Yes' : 'No'}</span>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-gray-600">SSL analysis in progress or no data available...</div>
          )}
        </div>
      )}

      {securityHeaders && (
        <div className="mb-8 p-6 bg-green-50 border border-green-200 rounded-lg">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="w-6 h-6 text-green-600" />
            Security Headers
          </h2>
          
          <div className="grid gap-3">
            <SecurityStatus 
              status={securityHeaders.strictTransportSecurity} 
              label="Strict-Transport-Security (HSTS)" 
            />
            <SecurityStatus 
              status={securityHeaders.xFrameOptions} 
              label="X-Frame-Options" 
            />
            <SecurityStatus 
              status={securityHeaders.xXssProtection} 
              label="X-XSS-Protection" 
            />
            <SecurityStatus 
              status={securityHeaders.contentSecurityPolicy} 
              label="Content-Security-Policy" 
            />
            <SecurityStatus 
              status={securityHeaders.xContentTypeOptions} 
              label="X-Content-Type-Options" 
            />
          </div>
        </div>
      )}

      {vulnerabilities && (
        <div className="p-6 bg-yellow-50 border border-yellow-200 rounded-lg">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-yellow-600" />
            Vulnerability Assessment
          </h2>
          
          <div className="space-y-4">
            <div>
              <h3 className="font-medium mb-2">Admin URLs Found:</h3>
              {vulnerabilities.adminUrls.length > 0 ? (
                <div className="space-y-1">
                  {vulnerabilities.adminUrls.map((admin, index) => (
                    <div key={index} className="flex items-center gap-2 text-sm">
                      <AlertTriangle className="w-4 h-4 text-yellow-500" />
                      <span className="font-mono">{admin.url}</span>
                      <span className="text-gray-600">(Status: {admin.status})</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex items-center gap-2 text-sm text-green-600">
                  <CheckCircle className="w-4 h-4" />
                  No common admin URLs found
                </div>
              )}
            </div>

            <div>
              <h3 className="font-medium mb-2">Directory Indexing:</h3>
              <div className="flex items-center gap-2 text-sm">
                {vulnerabilities.directoryIndexing ? (
                  <>
                    <XCircle className="w-4 h-4 text-red-500" />
                    <span className="text-red-600">Directory indexing appears to be enabled</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    <span className="text-green-600">Directory indexing not detected</span>
                  </>
                )}
              </div>
            </div>

            <div>
              <h3 className="font-medium mb-2">Sensitive Files:</h3>
              {vulnerabilities.sensitiveFiles.length > 0 ? (
                <div className="space-y-1">
                  {vulnerabilities.sensitiveFiles.map((file, index) => (
                    <div key={index} className="flex items-center gap-2 text-sm">
                      <AlertTriangle className="w-4 h-4 text-red-500" />
                      <span className="font-mono text-red-600">{file.file}</span>
                      <span className="text-gray-600">is accessible</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex items-center gap-2 text-sm text-green-600">
                  <CheckCircle className="w-4 h-4" />
                  No sensitive files found accessible
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityTab;
