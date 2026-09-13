document.addEventListener("DOMContentLoaded", () => {
    const scenarioSelect = document.getElementById("scenario-select");
    const scenarioDesc = document.getElementById("scenario-desc-text");
    const scenarioTag = document.getElementById("active-scenario-tag");
    const flagsContainer = document.getElementById("flags-container");
    const uploadForm = document.getElementById("upload-form");
    const fileInput = document.getElementById("file-input");
    const uploadMethodSelect = document.getElementById("upload-method");
    const authTokenInput = document.getElementById("auth-token");
    const btnUpload = document.getElementById("btn-upload");
    const progressContainer = document.getElementById("progress-container");
    const progressBarFill = document.getElementById("progress-bar-fill");
    const progressPercentage = document.getElementById("progress-percentage");
    const progressStatusText = document.getElementById("progress-status-text");

    const s1Data = document.getElementById("trace-s1-data");
    const s2Data = document.getElementById("trace-s2-data");
    const s3Data = document.getElementById("trace-s3-data");
    const filesTableBody = document.getElementById("files-table-body");
    const btnRefreshFiles = document.getElementById("btn-refresh-files");
    const btnClearTrace = document.getElementById("btn-clear-trace");

    let currentConfig = null;

    async function loadScenarios() {
        try {
            const res = await fetch("/api/scenarios");
            const data = await res.json();
            currentConfig = data.active_config;
            renderScenarioDetails(data.active_key, currentConfig);
        } catch (e) {
            console.error("Failed to load scenarios:", e);
        }
    }

    function renderScenarioDetails(key, cfg) {
        scenarioTag.textContent = key;
        scenarioDesc.textContent = cfg.description || "";
        flagsContainer.innerHTML = `
            <div class="flag-item">
                <span class="flag-dot ${cfg.require_auth_for_credentials ? 'safe' : 'vulnerable'}"></span>
                <span>Auth: ${cfg.require_auth_for_credentials ? 'Enforced' : 'Public (V1)'}</span>
            </div>
            <div class="flag-item">
                <span class="flag-dot ${cfg.expiry_seconds <= 300 ? 'safe' : 'vulnerable'}"></span>
                <span>TTL: ${cfg.expiry_seconds}s ${cfg.expiry_seconds > 300 ? '(V2)' : ''}</span>
            </div>
            <div class="flag-item">
                <span class="flag-dot ${cfg.enforce_type_and_size_limits ? 'safe' : 'vulnerable'}"></span>
                <span>Type/Size: ${cfg.enforce_type_and_size_limits ? 'Enforced' : 'Unrestricted (V3)'}</span>
            </div>
            <div class="flag-item">
                <span class="flag-dot ${!cfg.allow_file_overwrite ? 'safe' : 'vulnerable'}"></span>
                <span>Collision: ${!cfg.allow_file_overwrite ? 'UUID Namespaced' : 'Overwrites Allowed (V4)'}</span>
            </div>
            <div class="flag-item">
                <span class="flag-dot ${!cfg.public_read_acl ? 'safe' : 'vulnerable'}"></span>
                <span>ACL: ${!cfg.public_read_acl ? 'Private' : 'Public Read (V5)'}</span>
            </div>
            <div class="flag-item">
                <span class="flag-dot ${cfg.verify_callback_signature ? 'safe' : 'vulnerable'}"></span>
                <span>Callback: ${cfg.verify_callback_signature ? 'Verified' : 'Unchecked Spoofable (V6)'}</span>
            </div>
        `;
    }

    scenarioSelect.addEventListener("change", async () => {
        const selectedKey = scenarioSelect.value;
        try {
            const res = await fetch("/api/scenarios/set", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scenario_key: selectedKey })
            });
            const data = await res.json();
            currentConfig = data.config;
            renderScenarioDetails(data.active_key, currentConfig);
        } catch (e) {
            alert("Error switching scenario: " + e.message);
        }
    });

    async function loadFiles() {
        try {
            const res = await fetch("/api/files");
            const data = await res.json();
            if (!data.files || data.files.length === 0) {
                filesTableBody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No files registered yet.</td></tr>`;
                return;
            }
            filesTableBody.innerHTML = data.files.map(f => `
                <tr>
                    <td><strong>${escapeHtml(f.filename)}</strong><br><small class="text-muted">${escapeHtml(f.key)}</small></td>
                    <td>${formatBytes(f.file_size)}</td>
                    <td><span class="sub-badge ${f.verified ? 'safe' : 'vulnerable'}">${f.verified ? 'Verified' : 'Unverified'}</span></td>
                </tr>
            `).join("");
        } catch (e) {
            console.error("Failed to load files:", e);
        }
    }

    btnRefreshFiles.addEventListener("click", loadFiles);
    btnClearTrace.addEventListener("click", () => {
        s1Data.textContent = "Awaiting upload trigger...";
        s1Data.className = "step-data";
        s2Data.textContent = "Awaiting dispatch...";
        s2Data.className = "step-data";
        s3Data.textContent = "Awaiting completion...";
        s3Data.className = "step-data";
        progressContainer.classList.add("hidden");
    });

    uploadForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const file = fileInput.files[0];
        if (!file) {
            alert("Please select a file first.");
            return;
        }

        const method = uploadMethodSelect.value;
        const authToken = authTokenInput.value.trim();

        progressContainer.classList.remove("hidden");
        updateProgress(0, "Requesting Presigned Upload Credentials...");
        s1Data.textContent = "Requesting presigned upload URL from backend...";
        s1Data.className = "step-data";
        s2Data.textContent = "Pending Stage 1 response...";
        s2Data.className = "step-data";
        s3Data.textContent = "Pending Stage 2 completion...";
        s3Data.className = "step-data";
        btnUpload.disabled = true;

        try {
            // Stage 1
            const headers = { "Content-Type": "application/json" };
            if (authToken) {
                headers["Authorization"] = `Bearer ${authToken}`;
            }

            const credRes = await fetch("/api/get-upload-url", {
                method: "POST",
                headers: headers,
                body: JSON.stringify({
                    filename: file.name,
                    content_type: file.type || "application/octet-stream",
                    file_size: file.size,
                    upload_method: method
                })
            });

            if (!credRes.ok) {
                const errData = await credRes.json();
                s1Data.textContent = `[FAILED ${credRes.status}] ${errData.detail || "Access Denied"}`;
                s1Data.className = "step-data error";
                updateProgress(0, "Stage 1 Failed");
                btnUpload.disabled = false;
                return;
            }

            const credData = await credRes.json();
            s1Data.textContent = `[SUCCESS 200] Dispatched Key: ${credData.key}\nTTL: ${credData.expires_in_seconds}s | ACL: ${credData.acl}\nTarget Endpoint: ${credData.url.substring(0, 75)}...`;
            s1Data.className = "step-data success";

            // Stage 2
            updateProgress(30, `Uploading ${file.name} directly to Cloud Storage...`);
            s2Data.textContent = `Dispatching direct ${method} upload to cloud storage...`;

            if (credData.upload_type === "PUT") {
                await uploadViaPut(credData.url, file, credData.headers || {});
            } else {
                await uploadViaPost(credData.url, credData.fields, file);
            }

            s2Data.textContent = `[SUCCESS 200/204] Successfully uploaded ${file.name} directly to object storage!`;
            s2Data.className = "step-data success";
            updateProgress(75, "Direct upload complete! Notifying application backend...");

            // Stage 3
            s3Data.textContent = "Sending callback payload to /api/upload-complete...";
            const callbackRes = await fetch("/api/upload-complete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    key: credData.key,
                    filename: file.name,
                    file_size: file.size,
                    content_type: file.type || "application/octet-stream",
                    signature: credData.callback_token || "none"
                })
            });

            if (!callbackRes.ok) {
                const cbErr = await callbackRes.json();
                s3Data.textContent = `[REJECTED ${callbackRes.status}] ${cbErr.detail || "Callback verification failed"}`;
                s3Data.className = "step-data error";
                updateProgress(75, "Callback Rejected by Backend");
                btnUpload.disabled = false;
                return;
            }

            const cbData = await callbackRes.json();
            s3Data.textContent = `[ACCEPTED 200] ${cbData.message}\nRecord ID: ${cbData.record.id}`;
            s3Data.className = "step-data success";
            updateProgress(100, "Workflow Completed Successfully!");
            loadFiles();

        } catch (err) {
            console.error("Upload workflow error:", err);
            s2Data.textContent = `[ERROR] ${err.message}`;
            s2Data.className = "step-data error";
            updateProgress(0, "Workflow Encountered Error");
        } finally {
            btnUpload.disabled = false;
        }
    });

    function uploadViaPut(url, file, customHeaders) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open("PUT", url, true);
            for (const headerName in customHeaders) {
                xhr.setRequestHeader(headerName, customHeaders[headerName]);
            }
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const pct = Math.round(30 + (e.loaded / e.total) * 45);
                    updateProgress(pct, `Uploading directly to S3/MinIO (${Math.round((e.loaded / e.total) * 100)}%)...`);
                }
            };
            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(xhr.response);
                } else {
                    reject(new Error(`Storage returned HTTP ${xhr.status}: ${xhr.statusText}`));
                }
            };
            xhr.onerror = () => reject(new Error("Network error during direct storage upload."));
            xhr.send(file);
        });
    }

    function uploadViaPost(url, fields, file) {
        return new Promise((resolve, reject) => {
            const formData = new FormData();
            for (const key in fields) {
                formData.append(key, fields[key]);
            }
            formData.append("file", file);

            const xhr = new XMLHttpRequest();
            xhr.open("POST", url, true);
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const pct = Math.round(30 + (e.loaded / e.total) * 45);
                    updateProgress(pct, `Uploading via Presigned POST (${Math.round((e.loaded / e.total) * 100)}%)...`);
                }
            };
            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(xhr.response);
                } else {
                    reject(new Error(`Storage returned HTTP ${xhr.status}: ${xhr.statusText}`));
                }
            };
            xhr.onerror = () => reject(new Error("Network error during presigned POST upload."));
            xhr.send(formData);
        });
    }

    function updateProgress(percent, statusText) {
        progressBarFill.style.width = `${percent}%`;
        progressPercentage.textContent = `${percent}%`;
        progressStatusText.textContent = statusText;
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
    }

    function escapeHtml(str) {
        return (str || "").replace(/[&<>'"]/g, 
            tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
        );
    }

    loadScenarios();
    loadFiles();
});
