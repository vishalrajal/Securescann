import React, { useState } from 'react';
import { Github, Mail, Link, FileImage, FileText, AlertTriangle, Shield, ShieldCheck } from 'lucide-react';
import { scanUrl, scanFile } from './utils/virustotal';
import { ScanResults } from './components/ScanResults';
import type { ScanResult } from './utils/virustotal';

type ScanType = 'url' | 'pdf' | 'image';

function App() {
  const [scanType, setScanType] = useState<ScanType>('url');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsScanning(true);
    setError(null);

    try {
      let result;
      if (scanType === 'url') {
        if (!url.trim()) {
          throw new Error('Please enter a valid URL');
        }
        result = await scanUrl(url);
      } else if (file) {
        result = await scanFile(file);
      } else {
        throw new Error('Please select a file or enter a URL');
      }
      
      // Add 5 second delay before showing results
      await new Promise(resolve => setTimeout(resolve, 5000));
      setScanResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during scanning');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Navbar */}
      <nav className="border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Shield className="w-8 h-8 text-blue-500" />
              <span className="ml-2 text-xl font-bold">SecureScan</span>
            </div>
            <div className="flex items-center space-x-4">
              <a href="https://github.com/vishalrajal" target="_blank" rel="noopener noreferrer" className="hover:text-blue-500 transition-colors">
                <Github className="w-5 h-5" />
              </a>
              <a href="mailto:ifficial.vishalraja.org@gmail.com" className="hover:text-blue-500 transition-colors">
                <Mail className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-3xl mx-auto px-4 py-12">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">Secure File & URL Scanner</h1>
          <p className="text-gray-400">Advanced security scanning for URLs, PDFs, and images</p>
        </div>

        {error && (
          <div className="mb-8 p-4 bg-red-900/50 border border-red-500 rounded-lg">
            <div className="flex items-center text-red-500">
              <AlertTriangle className="w-5 h-5 mr-2" />
              <p>{error}</p>
            </div>
          </div>
        )}

        <form onSubmit={handleScan} className="space-y-8">
          {/* Scan Type Tabs */}
          <div className="flex justify-center bg-gray-800 rounded-lg p-1">
            <button
              type="button"
              onClick={() => setScanType('url')}
              className={`flex items-center px-4 py-2 rounded-md transition-colors ${
                scanType === 'url' ? 'bg-blue-500 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              <Link className="w-4 h-4 mr-2" />
              URL
            </button>
            <button
              type="button"
              onClick={() => setScanType('pdf')}
              className={`flex items-center px-4 py-2 rounded-md transition-colors ${
                scanType === 'pdf' ? 'bg-blue-500 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              <FileText className="w-4 h-4 mr-2" />
              PDF
            </button>
            <button
              type="button"
              onClick={() => setScanType('image')}
              className={`flex items-center px-4 py-2 rounded-md transition-colors ${
                scanType === 'image' ? 'bg-blue-500 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              <FileImage className="w-4 h-4 mr-2" />
              Image
            </button>
          </div>

          {/* Input Field */}
          {scanType === 'url' ? (
            <div className="relative">
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL to scan"
                className="w-full px-4 py-3 bg-gray-800 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none"
                required
              />
            </div>
          ) : (
            <div className="relative">
              <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                accept={scanType === 'pdf' ? '.pdf' : 'image/*'}
                className="w-full px-4 py-3 bg-gray-800 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-500 file:text-white hover:file:bg-blue-600"
                required
              />
            </div>
          )}

          {/* Start Scan Button */}
          <button
            type="submit"
            disabled={isScanning}
            className="w-full py-4 bg-blue-500 text-white rounded-lg font-semibold hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isScanning ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </span>
            ) : (
              'Start Deep Scan'
            )}
          </button>
        </form>

        {/* Warning Section */}
        <div className="mt-12 p-4 bg-gray-800 rounded-lg">
          <div className="flex items-center text-yellow-500 mb-2">
            <AlertTriangle className="w-5 h-5 mr-2" />
            <h3 className="font-semibold">Important Notice</h3>
          </div>
          <p className="text-gray-400 text-sm">
            SecureScan performs comprehensive security analysis using multiple detection engines. While highly accurate, always exercise caution when downloading files or visiting unknown websites.
          </p>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-12">
        <div className="max-w-7xl mx-auto px-4 py-6 text-center text-gray-400">
          <p>SecureScan by Vishalraja</p>
        </div>
      </footer>

      {/* Scan Results Modal */}
      {scanResult && (
        <ScanResults
          result={scanResult}
          onClose={() => setScanResult(null)}
        />
      )}
    </div>
  );
}

export default App;