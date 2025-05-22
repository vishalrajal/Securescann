import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';
import type { ScanResult } from '../utils/virustotal';

interface ScanResultsProps {
  result: ScanResult;
  onClose: () => void;
}

export function ScanResults({ result, onClose }: ScanResultsProps) {
  const threatLevel = result.positives === 0 ? 'safe' : 
    result.positives < 3 ? 'low' : 
    result.positives < 10 ? 'medium' : 'high';

  const getStatusColor = () => {
    switch (threatLevel) {
      case 'safe': return 'text-green-500';
      case 'low': return 'text-yellow-500';
      case 'medium': return 'text-orange-500';
      case 'high': return 'text-red-500';
      default: return 'text-gray-500';
    }
  };

  const getStatusIcon = () => {
    switch (threatLevel) {
      case 'safe': return <ShieldCheck className="w-12 h-12 text-green-500" />;
      case 'low': return <Shield className="w-12 h-12 text-yellow-500" />;
      case 'medium': return <ShieldAlert className="w-12 h-12 text-orange-500" />;
      case 'high': return <AlertTriangle className="w-12 h-12 text-red-500" />;
      default: return <Shield className="w-12 h-12 text-gray-500" />;
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 rounded-lg shadow-xl max-w-2xl w-full p-6 border border-gray-800">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center">
            {getStatusIcon()}
            <div className="ml-4">
              <h2 className="text-2xl font-bold">Scan Results</h2>
              <p className={`text-lg ${getStatusColor()}`}>
                {threatLevel.charAt(0).toUpperCase() + threatLevel.slice(1)} Risk Level
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            ✕
          </button>
        </div>

        <div className="space-y-6">
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-gray-800 p-4 rounded-lg text-center">
              <p className="text-gray-400 text-sm">Total Scans</p>
              <p className="text-2xl font-bold">{result.total}</p>
            </div>
            <div className="bg-gray-800 p-4 rounded-lg text-center">
              <p className="text-gray-400 text-sm">Detections</p>
              <p className="text-2xl font-bold text-red-500">{result.positives}</p>
            </div>
            <div className="bg-gray-800 p-4 rounded-lg text-center">
              <p className="text-gray-400 text-sm">Clean</p>
              <p className="text-2xl font-bold text-green-500">
                {result.total - result.positives}
              </p>
            </div>
          </div>

          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-lg font-semibold mb-4">Detailed Results</h3>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {Object.entries(result.scans).map(([scanner, data]) => (
                <div
                  key={scanner}
                  className="flex items-center justify-between py-2 border-b border-gray-700 last:border-0"
                >
                  <span className="text-gray-300">{scanner}</span>
                  <span className={data.detected ? 'text-red-500' : 'text-green-500'}>
                    {data.result || (data.detected ? 'Detected' : 'Clean')}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex justify-between items-center">
            <a
              href={result.permalink}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-500 hover:text-blue-400 transition-colors"
            >
              View Full Report
            </a>
            <button
              onClick={onClose}
              className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}