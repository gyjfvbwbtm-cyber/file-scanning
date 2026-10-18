const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs-extra');

const app = express();
const PORT = process.env.PORT || 3000;

const uploadDir = path.join(__dirname, 'uploads');
fs.ensureDirSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ 
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }
});

const DANGEROUS_EXTENSIONS = ['.exe', '.bat', '.cmd', '.vbs', '.scr', '.ps1', '.jar', '.pif', '.sh'];

// Main HTML Page (English & Named: File scanning)
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File scanning - Advanced Security & Threat Detector</title>
    
    <!-- Open Graph Meta Tags for Discord & Social Media Previews -->
    <meta property="og:title" content="File scanning - Secure File Analysis">
    <meta property="og:description" content="Advanced security scanner to detect malware, suspicious scripts, and vulnerabilities instantly.">
    <meta property="og:image" content="https://i.imgur.com/your-image-link.png">
    <meta property="og:url" content="https://file-scanning.onrender.com">
    <meta name="twitter:card" content="summary_large_image">

    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0d1117; color: #c9d1d9; }
        .glow-box { box-shadow: 0 0 25px rgba(56, 189, 248, 0.15); }
        .glow-red { box-shadow: 0 0 25px rgba(239, 68, 68, 0.25); }
        .glow-green { box-shadow: 0 0 25px rgba(34, 197, 94, 0.25); }
    </style>
</head>
<body class="min-h-screen flex flex-col justify-between items-center p-4">

    <header class="w-full max-w-4xl text-center my-8">
        <div class="inline-flex items-center gap-2 text-cyan-400 text-sm font-bold bg-cyan-950/50 px-4 py-1.5 rounded-full border border-cyan-800/50 mb-3">
            <span>🛡️ Cyber Security Threat Intelligence</span>
        </div>
        <h1 class="text-4xl md:text-5xl font-black text-white tracking-wide">File scanning</h1>
        <p class="text-gray-400 mt-2 text-base">Analyze any file instantly to ensure it is clean from malware and harmful scripts</p>
    </header>

    <main class="w-full max-w-3xl">
        <div id="drop-zone" class="glow-box bg-gray-900/80 border-2 border-dashed border-cyan-500/45 hover:border-cyan-400 transition-all rounded-2xl p-10 text-center cursor-pointer relative overflow-hidden">
            <input type="file" id="file-input" class="hidden">
            <div class="flex flex-col items-center justify-center gap-4">
                <div class="w-20 h-20 bg-cyan-500/10 rounded-full flex items-center justify-center text-cyan-400 text-4xl border border-cyan-500/30">
                    📂
                </div>
                <div>
                    <h3 class="text-xl font-bold text-white">Drag & drop your file here, or click to browse</h3>
                    <p class="text-sm text-gray-400 mt-1">Supports instant analysis for all file types (Max size: 50MB)</p>
                </div>
                <button class="mt-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold px-8 py-3 rounded-xl hover:opacity-90 transition shadow-lg">
                    Choose File
                </button>
            </div>
        </div>

        <div id="loading" class="hidden bg-gray-900 border border-gray-800 rounded-2xl p-8 text-center my-6">
            <div class="inline-block animate-spin rounded-full h-12 w-12 border-4 border-cyan-500 border-t-transparent mb-4"></div>
            <h3 class="text-lg font-bold text-white">Analyzing file for security threats...</h3>
            <p class="text-sm text-gray-400 mt-1">Extracting SHA-256 hash and inspecting inner code structures</p>
        </div>

        <div id="result-card" class="hidden bg-gray-900 border border-gray-800 rounded-2xl p-6 my-6 transition-all">
            <div class="flex items-center justify-between border-b border-gray-800 pb-4 mb-4">
                <div>
                    <span class="text-xs text-gray-400">File Name:</span>
                    <h4 id="res-filename" class="text-lg font-bold text-white">filename.exe</h4>
                </div>
                <div id="res-status" class="px-4 py-1.5 rounded-full text-sm font-bold">
                    🟢 Safe
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm mb-6">
                <div class="bg-gray-950 p-3 rounded-xl border border-gray-800">
                    <span class="text-gray-400 block text-xs">File Size:</span>
                    <span id="res-size" class="font-bold text-gray-200">0 MB</span>
                </div>
                <div class="bg-gray-950 p-3 rounded-xl border border-gray-800">
                    <span class="text-gray-400 block text-xs">Risk Score:</span>
                    <span id="res-score" class="font-bold text-gray-200">0%</span>
                </div>
                <div class="col-span-1 md:col-span-2 bg-gray-950 p-3 rounded-xl border border-gray-800 break-all">
                    <span class="text-gray-400 block text-xs">SHA-256 Digital Fingerprint:</span>
                    <span id="res-hash" class="font-mono text-cyan-400 text-xs">--</span>
                </div>
            </div>

            <div class="border-t border-gray-800 pt-4">
                <h5 class="text-sm font-bold text-white mb-2">Analysis Details:</h5>
                <ul id="res-details" class="space-y-2 text-sm"></ul>
            </div>
        </div>
    </main>

<footer class="text-center text-xs text-gray-500 py-6">
    © 2026 File scanning | Developed by KHALID ALFARES
</footer>

    <script>
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');
        const loading = document.getElementById('loading');
        const resultCard = document.getElementById('result-card');

        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('border-cyan-400'); });
        dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('border-cyan-400'); });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('border-cyan-400');
            if (e.dataTransfer.files.length) handleScan(e.dataTransfer.files[0]);
        });
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) handleScan(e.target.files[0]);
        });

        async function handleScan(file) {
            loading.classList.remove('hidden');
            resultCard.classList.add('hidden');
            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/api/scan', { method: 'POST', body: formData });
                const data = await response.json();
                loading.classList.add('hidden');
                if (data.success) {
                    showResults(data.result);
                } else {
                    alert(data.error || 'An error occurred during scanning.');
                }
            } catch (err) {
                loading.classList.add('hidden');
                alert('Failed to connect to server.');
            }
        }

        function showResults(res) {
            document.getElementById('res-filename').innerText = res.fileName;
            document.getElementById('res-size').innerText = res.fileSize;
            document.getElementById('res-score').innerText = res.score + '%';
            document.getElementById('res-hash').innerText = res.sha256;
            const statusElem = document.getElementById('res-status');
            statusElem.innerText = res.threatLevel;

            if (res.isSuspicious) {
                statusElem.className = 'px-4 py-1.5 rounded-full text-sm font-bold bg-red-950 text-red-400 border border-red-800';
                resultCard.className = 'bg-gray-900 border border-red-900/60 glow-red rounded-2xl p-6 my-6 transition-all';
            } else {
                statusElem.className = 'px-4 py-1.5 rounded-full text-sm font-bold bg-green-950 text-green-400 border border-green-800';
                resultCard.className = 'bg-gray-900 border border-green-900/60 glow-green rounded-2xl p-6 my-6 transition-all';
            }

            const detailsList = document.getElementById('res-details');
            detailsList.innerHTML = '';
            if (res.detectionDetails.length === 0) {
                detailsList.innerHTML = '<li class="text-green-400">✔️ No suspicious indicators or harmful patterns detected.</li>';
            } else {
                res.detectionDetails.forEach(item => {
                    const li = document.createElement('li');
                    li.className = 'text-red-400 flex items-center gap-2';
                    li.innerHTML = \`⚠️ <span>\${item}</span>\`;
                    detailsList.appendChild(li);
                });
            }
            resultCard.classList.remove('hidden');
        }
    </script>
</body>
</html>`);
});

// Scan Engine API
app.post('/api/scan', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Please upload a file first.' });

        const filePath = req.file.path;
        const fileName = req.file.originalname;
        const fileSize = req.file.size;
        const ext = path.extname(fileName).toLowerCase();
        const fileBuffer = await fs.readFile(filePath);

        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        let isSuspicious = false;
        let threatLevel = '🟢 Safe';
        let score = 0;
        const detectionDetails = [];

        if (DANGEROUS_EXTENSIONS.includes(ext)) {
            isSuspicious = true;
            score += 45;
            detectionDetails.push(`Sensitive executable format carrying automated execution risks (${ext})`);
        }

        const fileContent = fileBuffer.toString('utf8', 0, Math.min(fileBuffer.length, 500000));
        const suspiciousPatterns = [
            { pattern: /powershell\.exe/i, label: 'Hidden PowerShell execution command' },
            { pattern: /cmd\.exe\s+\/c/i, label: 'Command Prompt (CMD) shell invocation' },
            { pattern: /eval\(|exec\(/i, label: 'Obfuscated or dynamic script execution functions' },
            { pattern: /WScript\.Shell/i, label: 'Windows Scripting OS access attempt' },
            { pattern: /https?:\/\/[^\s"'<>]+/i, label: 'Embedded external network URLs' },
            { pattern: /base64_decode|atob/i, label: 'Base64 encoded strings or scripts' }
        ];

        suspiciousPatterns.forEach(item => {
            if (item.pattern.test(fileContent)) {
                isSuspicious = true;
                score += 20;
                detectionDetails.push(item.label);
            }
        });

        if (score >= 50) {
            threatLevel = '🔴 High Risk';
        } else if (score > 0) {
            threatLevel = '🟡 Suspicious';
        }

        await fs.unlink(filePath);

        res.json({
            success: true,
            result: {
                fileName,
                fileSize: (fileSize / (1024 * 1024)).toFixed(2) + ' MB',
                extension: ext || 'No Extension',
                sha256: hash,
                threatLevel,
                score: Math.min(score, 100),
                isSuspicious,
                detectionDetails
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'An error occurred while scanning the file.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
