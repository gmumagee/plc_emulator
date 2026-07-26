(() => {
  const PROTOCOL_LABELS = {
    modbus: "MODBUS/TCP",
    s7comm: "S7COMM",
    cip: "CIP / ETHERNET-IP",
    fins: "FINS",
    mc: "MC PROTOCOL",
    stublog: "STUBLOG",
  };

  const STATUS_POLL_MS = 2000;
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fleetEl = document.getElementById("fleet");
  const emptyStateEl = document.getElementById("emptyState");
  const cardTemplate = document.getElementById("cardTemplate");
  const countRunningEl = document.getElementById("countRunning");
  const countStoppedEl = document.getElementById("countStopped");
  const pageNoticeEl = document.getElementById("pageNotice");
  const savedDevicesListEl = document.getElementById("savedDevicesList");
  const savedDevicesEmptyEl = document.getElementById("savedDevicesEmpty");
  const openFaultLabBtn = document.getElementById("openFaultLabBtn");

  const overlay = document.getElementById("overlay");
  const form = document.getElementById("newInstanceForm");
  const panelTitleEl = document.getElementById("panelTitle");
  const formError = document.getElementById("formError");
  const privilegedNote = document.getElementById("privilegedNote");
  const authbindStatusEl = document.getElementById("authbindStatus");
  const hostSelect = document.getElementById("f-host-select");
  const hostCustomInput = document.getElementById("f-host-custom");
  const portInput = document.getElementById("f-port");
  const deviceTypeSelect = document.getElementById("f-device-type");
  const deviceTypeAvailabilityEl = document.getElementById("deviceTypeAvailability");
  const deviceTypeDetailEl = document.getElementById("deviceTypeDetail");
  const protocolDisplayEl = document.getElementById("protocolDisplay");
  const protocolDetailEl = document.getElementById("protocolDetail");
  const protocolWarningEl = document.getElementById("protocolWarning");
  const overrideEnabledEl = document.getElementById("f-override-enabled");
  const advancedPanelEl = document.getElementById("advancedPanel");
  const vendorInput = document.getElementById("f-vendor");
  const modelInput = document.getElementById("f-model");
  const productInput = document.getElementById("f-product");
  const saveIdInput = document.getElementById("f-save-id");
  const saveNameInput = document.getElementById("f-save-name");
  const saveConfigBtn = document.getElementById("saveConfigBtn");
  const faultOverlay = document.getElementById("faultOverlay");
  const faultForm = document.getElementById("faultForm");
  const faultInstanceSelect = document.getElementById("fault-instance");
  const faultPointSelect = document.getElementById("fault-point");
  const faultModeSelect = document.getElementById("fault-mode");
  const faultParamsPanel = document.getElementById("faultParamsPanel");
  const faultDriftRateRow = document.getElementById("fault-drift-rate-row");
  const faultDriftDirectionRow = document.getElementById("fault-drift-direction-row");
  const faultNoiseAmplitudeRow = document.getElementById("fault-noise-amplitude-row");
  const faultDriftRateInput = document.getElementById("fault-drift-rate");
  const faultDriftDirectionInput = document.getElementById("fault-drift-direction");
  const faultNoiseAmplitudeInput = document.getElementById("fault-noise-amplitude");
  const faultActiveListEl = document.getElementById("faultActiveList");
  const faultActiveEmptyEl = document.getElementById("faultActiveEmpty");
  const faultFormError = document.getElementById("faultFormError");
  const clearSelectedFaultBtn = document.getElementById("clearSelectedFaultBtn");
  const closeFaultButtons = [document.getElementById("closeFaultPanelBtn"), document.getElementById("cancelFaultBtn")];

  const openButtons = [document.getElementById("newInstanceBtn"), document.getElementById("emptyStateBtn")];
  const closeButtons = [document.getElementById("closePanelBtn"), document.getElementById("cancelBtn")];

  const openLogPanels = new Set();
  const openHmiPanels = new Set();
  const hmiStatusCache = new Map();
  const pendingHmiCommands = new Map();
  const hmiSetpointDrafts = new Map();
  const faultStatusCache = new Map();

  let authbindAvailable = null;
  let deviceTypes = {};
  let deviceErrors = [];
  let deviceTypeEntries = [];
  let hostAddresses = [];
  let lastList = [];
  let savedDevices = [];
  let pageNoticeTimer = null;

  function protocolLabel(protocol) {
    return PROTOCOL_LABELS[protocol] || String(protocol || "modbus").toUpperCase();
  }

  async function fetchJson(url, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});
    if (!["GET", "HEAD"].includes(method) && csrfToken && !headers.has("X-CSRFToken")) {
      headers.set("X-CSRFToken", csrfToken);
    }
    const response = await fetch(url, { ...options, headers });
    if (response.status === 401) {
      window.location.href = "/login";
      throw new Error("Authentication required");
    }
    let payload = {};
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      try {
        payload = await response.json();
      } catch {
        payload = {};
      }
    } else {
      try {
        payload = { raw: await response.text() };
      } catch {
        payload = {};
      }
    }
    return { response, payload };
  }

  function showPageNotice(message, state = "info") {
    if (!pageNoticeEl) return;
    pageNoticeEl.textContent = message;
    pageNoticeEl.dataset.state = state;
    pageNoticeEl.hidden = false;
    if (pageNoticeTimer) {
      clearTimeout(pageNoticeTimer);
    }
    pageNoticeTimer = setTimeout(() => {
      pageNoticeEl.hidden = true;
    }, 5000);
  }

  function escapeHtml(value) {
    return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function sortDeviceTypes(payload) {
    return Object.entries(payload).sort(([, left], [, right]) => {
      const classCompare = left.device_class.localeCompare(right.device_class);
      if (classCompare !== 0) return classCompare;
      const vendorCompare = left.vendor.localeCompare(right.vendor);
      if (vendorCompare !== 0) return vendorCompare;
      return left.model.localeCompare(right.model);
    });
  }

  function currentDeviceType() {
    return deviceTypes[deviceTypeSelect.value] || null;
  }

  function currentHostValue() {
    if (hostSelect.value === "__custom__") {
      return hostCustomInput.value.trim();
    }
    return hostSelect.value || "";
  }

  function deviceForInstance(inst) {
    return deviceTypes[inst.device_type] || null;
  }

  function faultablePointsForInstance(inst) {
    const device = deviceForInstance(inst);
    if (!device) return [];
    return (device.points || []).filter((point) => Array.isArray(point.fault?.modes) && point.fault.modes.length > 0);
  }

  function instancesWithFaultControls() {
    return [...lastList]
      .filter((inst) => faultablePointsForInstance(inst).length > 0)
      .sort((left, right) => left.name.localeCompare(right.name));
  }

  function setOverrideFields(device) {
    if (!device) return;
    vendorInput.value = device.vendor;
    modelInput.value = device.model;
    productInput.value = device.product_code;
  }

  function syncAdvancedVisibility() {
    const enabled = overrideEnabledEl.checked;
    advancedPanelEl.hidden = !enabled;
    vendorInput.disabled = !enabled;
    modelInput.disabled = !enabled;
    productInput.disabled = !enabled;
  }

  function formatPointValue(point, pointState) {
    if (!pointState) return "--";
    if (point.kind === "coil" || point.kind === "discrete_input") {
      const onLabel = point.hmi?.on_label || "ON";
      const offLabel = point.hmi?.off_label || "OFF";
      return pointState.value ? onLabel : offLabel;
    }
    const value = pointState.value;
    if (point.hmi?.format === "duration") {
      return `${Math.round(value)}s`;
    }
    if (typeof value === "number") {
      const decimals = String(point.scale || 1).includes(".") ? String(point.scale).split(".")[1].length : 0;
      const formatted = value.toFixed(Math.min(decimals, 2));
      return point.unit ? `${formatted}${point.unit}` : formatted;
    }
    return String(value);
  }

  function setControlState(button, isCurrent) {
    if (!button) return;
    button.dataset.current = isCurrent ? "true" : "false";
    button.setAttribute("aria-pressed", isCurrent ? "true" : "false");
  }

  function pointValueIsActive(pointState) {
    const value = pointState?.value;
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value !== 0;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (!normalized) return false;
      return normalized === "true" || normalized === "1" || normalized === "on" || normalized === "open" || normalized === "running";
    }
    return Boolean(value);
  }

  function syncSelectedDeviceType({ preservePort = false } = {}) {
    const device = currentDeviceType();
    if (!device) {
      protocolDisplayEl.textContent = "UNAVAILABLE";
      protocolDetailEl.textContent = "No device definitions loaded";
      protocolWarningEl.hidden = false;
      protocolWarningEl.textContent = "The device definition registry is empty or failed to load.";
      deviceTypeAvailabilityEl.textContent = "Unavailable";
      deviceTypeAvailabilityEl.dataset.state = "unavailable";
      deviceTypeDetailEl.textContent = "No device definition available.";
      return;
    }

    protocolDisplayEl.textContent = protocolLabel(device.protocol);
    protocolDetailEl.textContent = `Default port ${device.default_port}`;
    protocolWarningEl.hidden = device.implemented;
    protocolWarningEl.textContent = device.implemented
      ? ""
      : `${protocolLabel(device.protocol)} is mapped for this device, but that backend is not implemented in this build yet.`;
    deviceTypeAvailabilityEl.textContent = device.implemented ? "Available" : "Unavailable";
    deviceTypeAvailabilityEl.dataset.state = device.implemented ? "available" : "unavailable";
    deviceTypeDetailEl.textContent = `${device.device_class.toUpperCase()} - ${device.vendor} "${device.model}" - Simulation ${device.simulation.type}`;
    if (!preservePort) {
      portInput.value = device.default_port;
    }
    if (!overrideEnabledEl.checked) {
      setOverrideFields(device);
    }
    checkPrivilegedPort();
  }

  function populateDeviceTypeOptions(preferredType) {
    deviceTypeEntries = sortDeviceTypes(deviceTypes);
    deviceTypeSelect.innerHTML = "";
    for (const [key, device] of deviceTypeEntries) {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = `${device.vendor} ${device.model} [${device.device_class}]`;
      deviceTypeSelect.appendChild(option);
    }
    const firstType = deviceTypeEntries[0]?.[0] || "";
    deviceTypeSelect.value = preferredType && deviceTypes[preferredType] ? preferredType : firstType;
    syncSelectedDeviceType();
  }

  function defaultHostAddress() {
    const preferred = hostAddresses.find((value) => value !== "0.0.0.0" && value !== "127.0.0.1");
    return preferred || hostAddresses.find((value) => value === "127.0.0.1") || hostAddresses[0] || "127.0.0.1";
  }

  function syncHostInputVisibility() {
    const customSelected = hostSelect.value === "__custom__";
    hostCustomInput.hidden = !customSelected;
    hostCustomInput.disabled = !customSelected;
    hostCustomInput.required = customSelected;
    if (customSelected) {
      hostCustomInput.focus();
    }
  }

  function populateHostOptions(preferredHost) {
    hostSelect.innerHTML = "";
    for (const address of hostAddresses) {
      const option = document.createElement("option");
      option.value = address;
      option.textContent = address;
      hostSelect.appendChild(option);
    }
    const customOption = document.createElement("option");
    customOption.value = "__custom__";
    customOption.textContent = "Custom...";
    hostSelect.appendChild(customOption);

    if (preferredHost && hostAddresses.includes(preferredHost)) {
      hostSelect.value = preferredHost;
      hostCustomInput.value = "";
    } else if (preferredHost) {
      hostSelect.value = "__custom__";
      hostCustomInput.value = preferredHost;
    } else {
      hostSelect.value = defaultHostAddress();
      hostCustomInput.value = "";
    }
    syncHostInputVisibility();
  }

  async function loadDeviceTypes() {
    const { response, payload } = await fetchJson("/api/device-types");
    if (!response.ok) {
      throw new Error(`Failed to load device definitions (${response.status})`);
    }
    deviceTypes = payload.devices || {};
    deviceErrors = payload.errors || [];
    populateDeviceTypeOptions();
  }

  async function loadHostAddresses() {
    const { response, payload } = await fetchJson("/api/host-addresses");
    if (!response.ok) {
      throw new Error(`Failed to load host addresses (${response.status})`);
    }
    hostAddresses = payload.addresses || [];
    populateHostOptions();
  }

  async function refreshSavedDevices() {
    const { response, payload } = await fetchJson("/api/saved-devices");
    if (!response.ok) {
      throw new Error(payload.error || `Failed to load saved configs (${response.status})`);
    }
    savedDevices = payload.saved_devices || [];
    renderSavedDevices();
  }

  function currentFaultInstance() {
    return lastList.find((inst) => inst.id === faultInstanceSelect.value) || null;
  }

  function currentFaultPoint() {
    const inst = currentFaultInstance();
    if (!inst) return null;
    return faultablePointsForInstance(inst).find((point) => point.id === faultPointSelect.value) || null;
  }

  function syncFaultParamVisibility() {
    const mode = faultModeSelect.value;
    const showDrift = mode === "drift";
    const showNoise = mode === "noise";
    faultParamsPanel.hidden = !(showDrift || showNoise);
    faultDriftRateRow.hidden = !showDrift;
    faultDriftDirectionRow.hidden = !showDrift;
    faultNoiseAmplitudeRow.hidden = !showNoise;
  }

  function syncFaultModeOptions(preferredMode) {
    const point = currentFaultPoint();
    faultModeSelect.innerHTML = "";
    const modes = point?.fault?.modes || [];
    for (const mode of modes) {
      const option = document.createElement("option");
      option.value = mode;
      option.textContent = mode.replace(/_/g, " ");
      faultModeSelect.appendChild(option);
    }
    faultModeSelect.value = preferredMode && modes.includes(preferredMode) ? preferredMode : (modes[0] || "");
    syncFaultParamVisibility();
  }

  function syncFaultPointOptions(preferredPointId) {
    const inst = currentFaultInstance();
    const points = inst ? faultablePointsForInstance(inst) : [];
    faultPointSelect.innerHTML = "";
    for (const point of points) {
      const option = document.createElement("option");
      option.value = point.id;
      option.textContent = `${point.label} (${point.id})`;
      faultPointSelect.appendChild(option);
    }
    faultPointSelect.value = preferredPointId && points.some((point) => point.id === preferredPointId)
      ? preferredPointId
      : (points[0]?.id || "");
    syncFaultModeOptions();
  }

  function populateFaultInstanceOptions(preferredId) {
    const instances = instancesWithFaultControls();
    faultInstanceSelect.innerHTML = "";
    for (const inst of instances) {
      const option = document.createElement("option");
      option.value = inst.id;
      option.textContent = `${inst.name} (${inst.host}:${inst.port})`;
      faultInstanceSelect.appendChild(option);
    }
    faultInstanceSelect.value = preferredId && instances.some((inst) => inst.id === preferredId)
      ? preferredId
      : (instances[0]?.id || "");
    syncFaultPointOptions();
  }

  function renderFaultActiveList() {
    const inst = currentFaultInstance();
    const cache = inst ? faultStatusCache.get(inst.id) : null;
    const faults = cache?.active_faults || [];
    faultActiveListEl.innerHTML = "";
    faultActiveEmptyEl.hidden = faults.length > 0;
    for (const fault of faults) {
      const pill = document.createElement("div");
      pill.className = "active-fault-pill";
      const suffixParts = [];
      if (fault.mode === "drift" && fault.params?.drift_rate_per_sec !== undefined) {
        suffixParts.push(`rate ${fault.params.drift_rate_per_sec}/s`);
      }
      if (fault.mode === "noise" && fault.params?.amplitude !== undefined) {
        suffixParts.push(`amp ${fault.params.amplitude}`);
      }
      pill.textContent = `${fault.point} -> ${fault.mode}${suffixParts.length ? ` (${suffixParts.join(", ")})` : ""}`;
      faultActiveListEl.appendChild(pill);
    }
  }

  async function refreshFaultStatus(instanceId) {
    if (!instanceId) return;
    const { response, payload } = await fetchJson(`/api/instances/${instanceId}/faults`);
    if (!response.ok) {
      throw new Error(payload.error || "Failed to load fault status.");
    }
    faultStatusCache.set(instanceId, payload);
    renderFaultActiveList();
  }

  async function openFaultOverlay(preferredInstanceId = "") {
    populateFaultInstanceOptions(preferredInstanceId);
    faultFormError.hidden = true;
    faultFormError.textContent = "";
    faultOverlay.hidden = false;
    if (!faultInstanceSelect.value) {
      renderFaultActiveList();
      return;
    }
    await refreshFaultStatus(faultInstanceSelect.value);
  }

  function closeFaultOverlay() {
    faultOverlay.hidden = true;
    faultFormError.hidden = true;
    faultFormError.textContent = "";
  }

  async function checkPrivilegedPort() {
    const port = parseInt(portInput.value, 10);
    if (!port || port >= 1024) {
      privilegedNote.hidden = true;
      return;
    }
    try {
      const { payload } = await fetchJson(`/api/authbind-status?port=${encodeURIComponent(port)}`);
      authbindAvailable = payload.available;
      if (!payload.available) {
        authbindStatusEl.textContent = "authbind was not found on this host - launch may fail unless run as root.";
      } else if (payload.configured) {
        authbindStatusEl.textContent = `authbind is installed and port ${port} is configured for ${payload.expected_owner}.`;
      } else {
        authbindStatusEl.textContent = `authbind is installed, but port ${port} is not configured for ${payload.expected_owner} yet.`;
      }
    } catch {
      authbindAvailable = false;
      authbindStatusEl.textContent = "Unable to verify authbind configuration for this port.";
    }
    privilegedNote.hidden = false;
  }

  function resetFormDefaults() {
    form.reset();
    saveIdInput.value = "";
    saveNameInput.value = "";
    panelTitleEl.textContent = "Configure Device";
    formError.hidden = true;
    formError.textContent = "";
    document.getElementById("f-autostart").checked = true;
    overrideEnabledEl.checked = false;
    syncAdvancedVisibility();
    populateDeviceTypeOptions();
    populateHostOptions();
    checkPrivilegedPort();
  }

  function openOverlay({ savedDevice = null } = {}) {
    resetFormDefaults();
    if (savedDevice) {
      const config = savedDevice.config || {};
      const device = deviceTypes[savedDevice.device_type_id] || null;
      if (!device) {
        showPageNotice(`Saved config "${savedDevice.name}" references a device type that is no longer available.`, "error");
        return;
      }
      panelTitleEl.textContent = "Edit Saved Config";
      saveIdInput.value = String(savedDevice.id);
      saveNameInput.value = savedDevice.name || "";
      populateDeviceTypeOptions(savedDevice.device_type_id);
      populateHostOptions(config.host || "");
      document.getElementById("f-name").value = config.name || "";
      document.getElementById("f-port").value = config.port || device.default_port;
      document.getElementById("f-unit").value = config.unit_id ?? 1;
      document.getElementById("f-verbose").checked = Boolean(config.verbose);
      document.getElementById("f-autostart").checked = config.autostart !== false;

      const overrideEnabled =
        Boolean(config.override_identity) ||
        config.vendor !== device.vendor ||
        config.model !== device.model ||
        config.product_code !== device.product_code;
      overrideEnabledEl.checked = overrideEnabled;
      syncAdvancedVisibility();
      if (overrideEnabled) {
        vendorInput.value = config.vendor || device.vendor;
        modelInput.value = config.model || device.model;
        productInput.value = config.product_code || device.product_code;
      } else {
        setOverrideFields(device);
      }
      syncSelectedDeviceType({ preservePort: true });
    }
    overlay.hidden = false;
    document.getElementById("f-name").focus();
  }

  function closeOverlay() {
    overlay.hidden = true;
    resetFormDefaults();
  }

  function buildInstancePayload({ requireImplemented }) {
    const selectedType = currentDeviceType();
    if (!selectedType) {
      throw new Error("No device definition is available.");
    }
    if (requireImplemented && !selectedType.implemented) {
      throw new Error(`${protocolLabel(selectedType.protocol)} is not implemented in this build yet.`);
    }
    const payload = {
      name: document.getElementById("f-name").value.trim(),
      host: currentHostValue(),
      port: parseInt(document.getElementById("f-port").value, 10),
      unit_id: parseInt(document.getElementById("f-unit").value, 10),
      device_type: deviceTypeSelect.value || null,
      verbose: document.getElementById("f-verbose").checked,
      autostart: document.getElementById("f-autostart").checked,
      override_identity: overrideEnabledEl.checked,
    };
    if (overrideEnabledEl.checked) {
      payload.vendor = vendorInput.value.trim() || selectedType.vendor;
      payload.model = modelInput.value.trim() || selectedType.model;
      payload.product_code = productInput.value.trim() || selectedType.product_code;
      payload.device_class = selectedType.device_class;
    }
    return payload;
  }

  function colorizeLogLine(line) {
    if (/\bWARNING\b/.test(line)) return `<span class="lvl-warning">${escapeHtml(line)}</span>`;
    if (/\bERROR\b|Traceback/.test(line)) return `<span class="lvl-error">${escapeHtml(line)}</span>`;
    if (/\bINFO\b/.test(line)) return `<span class="lvl-info">${escapeHtml(line)}</span>`;
    return escapeHtml(line);
  }

  function replaceConsoleHtml(preEl, nextHtml, emptyText) {
    const pinnedTop = preEl.scrollTop <= 10;
    const html = nextHtml || escapeHtml(emptyText);
    if (preEl.innerHTML !== html) {
      preEl.innerHTML = html;
    }
    if (pinnedTop) {
      preEl.scrollTop = 0;
    }
  }

  function reverseLogHtml(text) {
    const normalized = String(text || "").replace(/\r\n/g, "\n");
    if (!normalized) return "";
    const lines = normalized.split("\n");
    if (lines[lines.length - 1] === "") {
      lines.pop();
    }
    return lines.reverse().map(colorizeLogLine).join("\n");
  }

  async function refreshLogs(id, preEl) {
    try {
      const { payload } = await fetchJson(`/api/instances/${id}/logs?lines=200`);
      replaceConsoleHtml(preEl, reverseLogHtml(payload.log), "(no log output yet)");
    } catch {
      // Ignore transient errors during restart.
    }
  }

  function formatClock(ts) {
    if (!ts) return "--:--:--";
    return new Date(ts * 1000).toLocaleTimeString();
  }

  function pendingCommandSatisfied(statusBundle, commandId) {
    const status = statusBundle?.status || {};
    if (status.last_command_id === commandId) return true;
    return (status.recent_events || []).some((event) => event.command_id === commandId);
  }

  async function refreshHmiStatus(hmiId) {
    const { response, payload } = await fetchJson(`/api/hmi/${hmiId}/status`);
    if (!response.ok) {
      hmiStatusCache.delete(hmiId);
      hmiSetpointDrafts.delete(hmiId);
      return;
    }
    hmiStatusCache.set(hmiId, payload);
    const pending = pendingHmiCommands.get(hmiId);
    if (pending && pendingCommandSatisfied(payload, pending.commandId)) {
      pendingHmiCommands.delete(hmiId);
    }
  }

  async function refreshOpenHmiStatuses(list) {
    const activeHmiIds = list
      .filter((inst) => openHmiPanels.has(inst.id) && inst.hmi?.id)
      .map((inst) => inst.hmi.id);
    await Promise.all(activeHmiIds.map((hmiId) => refreshHmiStatus(hmiId)));
  }

  async function openHmi(inst) {
    if (!inst.hmi_supported) {
      alert(`HMI client support for ${protocolLabel(inst.protocol)} is not implemented in this build.`);
      return;
    }
    const { response, payload } = await fetchJson(`/api/instances/${inst.id}/hmi`, { method: "POST" });
    if (!response.ok) {
      alert(payload.error || "Failed to open HMI.");
      return;
    }
    openHmiPanels.add(inst.id);
    if (payload.hmi?.id) {
      hmiStatusCache.set(payload.hmi.id, { hmi: payload.hmi, status: payload.status });
    }
    await refresh();
  }

  function closeHmi(instId) {
    openHmiPanels.delete(instId);
    render(lastList);
  }

  async function stopHmi(instId, hmiId) {
    await fetchJson(`/api/hmi/${hmiId}/stop`, { method: "POST" });
    pendingHmiCommands.delete(hmiId);
    await refresh();
    openHmiPanels.add(instId);
    render(lastList);
  }

  async function removeHmi(instId, hmiId) {
    if (!confirm("Delete this HMI client?")) return;
    await fetchJson(`/api/hmi/${hmiId}`, { method: "DELETE" });
    pendingHmiCommands.delete(hmiId);
    hmiStatusCache.delete(hmiId);
    hmiSetpointDrafts.delete(hmiId);
    openHmiPanels.delete(instId);
    refresh();
  }

  async function sendHmiCommand(hmiId, pointId, value, label) {
    const { response, payload } = await fetchJson(`/api/hmi/${hmiId}/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ point_id: pointId, value }),
    });
    if (!response.ok) {
      alert(payload.error || "Failed to send HMI command.");
      return;
    }
    pendingHmiCommands.set(hmiId, { commandId: payload.command_id, label, sentAt: Date.now() });
    render(lastList);
    setTimeout(() => refresh(), 350);
  }

  function renderHmiEvents(preEl, status) {
    const events = status?.recent_events || [];
    if (events.length === 0) {
      replaceConsoleHtml(preEl, "", "(no HMI events yet)");
      return;
    }
    replaceConsoleHtml(
      preEl,
      [...events]
        .reverse()
        .map((event) => {
          const line = `[${formatClock(event.ts)}] ${event.message}`;
          if (event.type === "error") return `<span class="lvl-error">${escapeHtml(line)}</span>`;
          if (event.type === "command") return `<span class="lvl-info">${escapeHtml(line)}</span>`;
          return escapeHtml(line);
        })
        .join("\n"),
      "(no HMI events yet)"
    );
  }

  function renderGaugeCard(point, pointState) {
    const numericValue = typeof pointState?.value === "number" ? pointState.value : 0;
    const percent = Math.max(0, Math.min(100, numericValue));
    return `
      <div class="hmi-gauge-card">
        <div class="tank-gauge">
          <div class="tank-gauge-fill" style="height: ${percent}%"></div>
        </div>
        <div class="tank-gauge-caption">${escapeHtml(point.label)}</div>
        <div class="tank-gauge-value">${escapeHtml(formatPointValue(point, pointState))}</div>
      </div>
    `;
  }

  function renderReadoutCard(point, pointState) {
    return `
      <div class="hmi-readout-card">
        <dt>${escapeHtml(point.label)}</dt>
        <dd>${escapeHtml(formatPointValue(point, pointState))}</dd>
      </div>
    `;
  }

  function renderAlarmWidget(point, pointState) {
    const bits = point.hmi?.bits || [];
    return `
      <div class="alarm-widget">
        <div class="alarm-widget-title">${escapeHtml(point.label)}</div>
        <div class="alarm-strip">
          ${bits.map((entry) => {
            const active = ((pointState?.raw || 0) & (1 << entry.bit)) !== 0;
            return `
              <div class="alarm-pill" data-active="${active ? "true" : "false"}">
                <span class="alarm-led"></span>
                <span>${escapeHtml(entry.label)}</span>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    `;
  }

  function renderToggleControl(point, _pointState, hmiId, disabled) {
    const onLabel = point.hmi?.on_label || "On";
    const offLabel = point.hmi?.off_label || "Off";
    return `
      <div class="control-group">
        <span class="control-label">${escapeHtml(point.label)}</span>
        <button class="btn btn-sm btn-start" data-action="write-toggle" data-hmi-id="${hmiId}" data-point-id="${point.id}" data-value="true" ${disabled ? "disabled" : ""}>${escapeHtml(onLabel)}</button>
        <button class="btn btn-sm btn-stop" data-action="write-toggle" data-hmi-id="${hmiId}" data-point-id="${point.id}" data-value="false" ${disabled ? "disabled" : ""}>${escapeHtml(offLabel)}</button>
      </div>
    `;
  }

  function renderSetpointControl(point, pointState, hmiId, disabled) {
    const draftState = hmiSetpointDrafts.get(hmiId);
    let value = "";
    if (draftState?.focused) {
      value = draftState.value;
    } else if (pointState && typeof pointState.value === "number") {
      value = String(pointState.value);
      hmiSetpointDrafts.set(hmiId, { value, focused: false });
    } else if (draftState?.value) {
      value = draftState.value;
    }
    const min = point.hmi?.min ?? (point.unit === "%" ? 0 : "");
    const max = point.hmi?.max ?? (point.unit === "%" ? 100 : "");
    const step = point.hmi?.step ?? (String(point.scale || 1).includes(".") ? point.scale : "1");
    return `
      <form class="hmi-setpoint-form" data-action="setpoint-submit" data-hmi-id="${hmiId}" data-point-id="${point.id}">
        <label>${escapeHtml(point.label)}</label>
        <input class="hmi-setpoint-input" data-hmi-id="${hmiId}" data-point-id="${point.id}" type="number" ${min !== "" ? `min="${min}"` : ""} ${max !== "" ? `max="${max}"` : ""} step="${step}" value="${escapeHtml(value)}" placeholder="${escapeHtml(formatPointValue(point, pointState))}" ${disabled ? "disabled" : ""}>
        <button class="btn btn-sm btn-primary" type="submit" ${disabled ? "disabled" : ""}>Apply</button>
      </form>
    `;
  }

  function controlSignature(togglePoints, setpointPoints, hmiId) {
    return JSON.stringify({
      hmiId,
      toggles: togglePoints.map((point) => point.id),
      setpoints: setpointPoints.map((point) => point.id),
    });
  }

  function syncSetpointControlValues(controlsEl, setpointPoints, pointsSnapshot, hmiId, disabled) {
    for (const point of setpointPoints) {
      const formEl = controlsEl.querySelector(`.hmi-setpoint-form[data-point-id="${point.id}"]`);
      if (!formEl) continue;
      const input = formEl.querySelector(".hmi-setpoint-input");
      const button = formEl.querySelector('button[type="submit"]');
      if (!(input instanceof HTMLInputElement)) continue;

      const pointState = pointsSnapshot[point.id];
      const draftState = hmiSetpointDrafts.get(hmiId);
      const min = point.hmi?.min ?? (point.unit === "%" ? 0 : "");
      const max = point.hmi?.max ?? (point.unit === "%" ? 100 : "");
      const step = point.hmi?.step ?? (String(point.scale || 1).includes(".") ? point.scale : "1");

      if (min !== "") input.min = String(min); else input.removeAttribute("min");
      if (max !== "") input.max = String(max); else input.removeAttribute("max");
      input.step = String(step);
      input.placeholder = formatPointValue(point, pointState);
      input.disabled = disabled;
      if (button) button.disabled = disabled;

      if (document.activeElement !== input) {
        let nextValue = "";
        if (pointState && typeof pointState.value === "number") {
          nextValue = String(pointState.value);
          hmiSetpointDrafts.set(hmiId, { value: nextValue, focused: false });
        } else if (draftState?.value) {
          nextValue = draftState.value;
        }
        if (input.value !== nextValue) {
          input.value = nextValue;
        }
      }
    }
  }

  function syncToggleControlValues(controlsEl, togglePoints, pointsSnapshot, disabled) {
    for (const point of togglePoints) {
      const onButton = controlsEl.querySelector(`button[data-point-id="${point.id}"][data-value="true"]`);
      const offButton = controlsEl.querySelector(`button[data-point-id="${point.id}"][data-value="false"]`);
      const onLabel = point.hmi?.on_label || "On";
      const offLabel = point.hmi?.off_label || "Off";
      const currentState = pointValueIsActive(pointsSnapshot[point.id]);

      if (onButton) {
        onButton.textContent = onLabel;
        onButton.disabled = disabled;
        setControlState(onButton, currentState);
      }
      if (offButton) {
        offButton.textContent = offLabel;
        offButton.disabled = disabled;
        setControlState(offButton, !currentState);
      }
    }
  }

  function renderHmiPanel(inst, card) {
    const panel = card.querySelector(".hmi-panel");
    const panelOpen = openHmiPanels.has(inst.id);
    panel.hidden = !panelOpen;

    const classTag = card.querySelector(".class-tag");
    classTag.textContent = (inst.device_class || "device").toUpperCase();
    classTag.className = "protocol-tag class-tag";

    const hmiTag = card.querySelector(".hmi-tag");
    if (!inst.hmi_supported) {
      hmiTag.textContent = "HMI N/A";
      hmiTag.dataset.state = "unsupported";
    } else if (inst.hmi?.running) {
      hmiTag.textContent = "HMI ATTACHED";
      hmiTag.dataset.state = "running";
    } else if (inst.hmi) {
      hmiTag.textContent = "HMI STOPPED";
      hmiTag.dataset.state = "stopped";
    } else {
      hmiTag.textContent = "NO HMI";
      hmiTag.dataset.state = "idle";
    }

    const openBtn = card.querySelector(".btn-hmi");
    openBtn.disabled = !inst.hmi_supported;
    openBtn.textContent = inst.hmi_supported ? "Open HMI" : "HMI N/A";
    openBtn.dataset.action = "open-hmi";
    openBtn.dataset.instanceId = inst.id;

    if (!panelOpen) return;

    const device = deviceForInstance(inst);
    const hmi = inst.hmi;
    const bundle = hmi?.id ? hmiStatusCache.get(hmi.id) : null;
    const status = bundle?.status || null;
    const pointsSnapshot = status?.snapshot?.points || {};
    const hmiPoints = device?.points?.filter((point) => point.hmi?.widget) || [];
    const controlsDisabled = !hmi?.running || !hmi.supported;

    panel.querySelector(".hmi-panel-subtitle").textContent = hmi
      ? `${(inst.device_class || "device").toUpperCase()} - ${protocolLabel(hmi.protocol)} polling ${hmi.host}:${hmi.port} every ${hmi.poll_interval.toFixed(1)}s`
      : "Launching HMI client...";

    const linkStateEl = panel.querySelector(".hmi-link-state");
    if (!hmi) {
      linkStateEl.textContent = "STARTING";
      linkStateEl.dataset.state = "starting";
    } else {
      const stateLabel = (status?.state || (hmi.running ? "starting" : "stopped")).toUpperCase();
      linkStateEl.textContent = stateLabel;
      linkStateEl.dataset.state = status?.state || (hmi.running ? "starting" : "stopped");
    }

    const bannerEl = panel.querySelector(".hmi-banner");
    if (!device) {
      bannerEl.hidden = false;
      bannerEl.textContent = "Device metadata missing for this HMI.";
      bannerEl.dataset.state = "error";
    } else if (!hmi) {
      bannerEl.hidden = false;
      bannerEl.textContent = "Starting HMI client...";
      bannerEl.dataset.state = "info";
    } else if (status?.error) {
      bannerEl.hidden = false;
      bannerEl.textContent = status.error;
      bannerEl.dataset.state = status.state === "unsupported" ? "warn" : "error";
    } else if (!hmi.running) {
      bannerEl.hidden = false;
      bannerEl.textContent = "HMI client is stopped.";
      bannerEl.dataset.state = "warn";
    } else if (!status?.connected) {
      bannerEl.hidden = false;
      bannerEl.textContent = "Waiting for target device or first poll result...";
      bannerEl.dataset.state = "warn";
    } else {
      bannerEl.hidden = false;
      bannerEl.textContent = `Last poll ${formatClock(status.last_poll_ts)} over ${protocolLabel(hmi.protocol)}.`;
      bannerEl.dataset.state = "info";
    }

    const gaugePoints = hmiPoints.filter((point) => point.hmi.widget === "gauge");
    const readoutPoints = hmiPoints.filter((point) => point.hmi.widget === "readout");
    const alarmPoints = hmiPoints.filter((point) => point.hmi.widget === "alarm_bits");
    const togglePoints = hmiPoints.filter((point) => point.hmi.widget === "toggle");
    const setpointPoints = hmiPoints.filter((point) => point.hmi.widget === "setpoint");

    const primaryZone = panel.querySelector(".hmi-primary-zone");
    const secondaryZone = panel.querySelector(".hmi-secondary-zone");
    primaryZone.innerHTML = gaugePoints.length
      ? gaugePoints.map((point) => renderGaugeCard(point, pointsSnapshot[point.id])).join("")
      : `<div class="hmi-summary-card"><div class="hmi-summary-title">${escapeHtml(device.display_name || `${device.vendor} ${device.model}`)}</div><div class="hmi-summary-body">${escapeHtml(device.device_class.toUpperCase())}</div></div>`;

    secondaryZone.innerHTML = `
      <div class="hmi-data-stack">
        ${readoutPoints.length ? `<dl class="hmi-readout-grid">${readoutPoints.map((point) => renderReadoutCard(point, pointsSnapshot[point.id])).join("")}</dl>` : `<div class="hmi-empty">No readouts defined for this device.</div>`}
        ${alarmPoints.map((point) => renderAlarmWidget(point, pointsSnapshot[point.id])).join("")}
      </div>
    `;

    const controlsEl = panel.querySelector(".hmi-controls");
    const signature = controlSignature(togglePoints, setpointPoints, hmi?.id || "");
    const activeElement = document.activeElement;
    const focusedSetpointInput =
      activeElement instanceof HTMLInputElement && activeElement.classList.contains("hmi-setpoint-input") && controlsEl.contains(activeElement)
        ? activeElement
        : null;
    if (controlsEl.dataset.signature !== signature && !focusedSetpointInput) {
      controlsEl.innerHTML = [
        ...togglePoints.map((point) => renderToggleControl(point, pointsSnapshot[point.id], hmi?.id || "", controlsDisabled)),
        ...setpointPoints.map((point) => renderSetpointControl(point, pointsSnapshot[point.id], hmi?.id || "", controlsDisabled)),
      ].join("") || `<div class="hmi-empty">No operator controls for this device.</div>`;
      controlsEl.dataset.signature = signature;
    } else if (!controlsEl.dataset.signature) {
      controlsEl.innerHTML = [
        ...togglePoints.map((point) => renderToggleControl(point, pointsSnapshot[point.id], hmi?.id || "", controlsDisabled)),
        ...setpointPoints.map((point) => renderSetpointControl(point, pointsSnapshot[point.id], hmi?.id || "", controlsDisabled)),
      ].join("") || `<div class="hmi-empty">No operator controls for this device.</div>`;
      controlsEl.dataset.signature = signature;
    }

    syncToggleControlValues(controlsEl, togglePoints, pointsSnapshot, controlsDisabled);
    syncSetpointControlValues(controlsEl, setpointPoints, pointsSnapshot, hmi?.id || "", controlsDisabled);

    const pending = hmi?.id ? pendingHmiCommands.get(hmi.id) : null;
    const commandStatusEl = panel.querySelector(".hmi-command-status");
    if (pending) {
      commandStatusEl.textContent = `Sending ${pending.label}...`;
      commandStatusEl.dataset.state = "pending";
    } else if (status?.last_poll_ts) {
      commandStatusEl.textContent = `Polled ${formatClock(status.last_poll_ts)} from ${hmi ? hmi.host : inst.host}:${hmi ? hmi.port : inst.port}`;
      commandStatusEl.dataset.state = "idle";
    } else {
      commandStatusEl.textContent = "No poll data yet.";
      commandStatusEl.dataset.state = "idle";
    }

    const stopBtn = panel.querySelector(".btn-hmi-stop");
    const deleteBtn = panel.querySelector(".btn-hmi-delete");
    const closeBtn = panel.querySelector(".btn-hmi-close");
    stopBtn.disabled = !hmi?.running;
    stopBtn.dataset.action = "stop-hmi";
    stopBtn.dataset.instanceId = inst.id;
    stopBtn.dataset.hmiId = hmi?.id || "";
    deleteBtn.dataset.action = "delete-hmi";
    deleteBtn.dataset.instanceId = inst.id;
    deleteBtn.dataset.hmiId = hmi?.id || "";
    closeBtn.dataset.action = "close-hmi";
    closeBtn.dataset.instanceId = inst.id;

    renderHmiEvents(panel.querySelector(".hmi-log-console"), status);
  }

  function createCardElement() {
    const node = cardTemplate.content.cloneNode(true);
    return node.querySelector(".card");
  }

  function updateCard(inst, card) {
    card.dataset.id = inst.id;
    card.dataset.running = String(inst.running);
    card.querySelector(".card-name").textContent = inst.name;
    card.querySelector(".card-subtitle").textContent = `${inst.vendor} / ${inst.model}`;
    card.querySelector(".protocol-tag").textContent = protocolLabel(inst.protocol);
    card.querySelector(".status-label").textContent = inst.running ? "RUNNING" : "STOPPED";
    card.querySelector(".readout-address").textContent = `${inst.host}:${inst.port}`;
    card.querySelector(".readout-unit").textContent = inst.unit_id;
    card.querySelector(".readout-pid").textContent = inst.pid || "-";

    const startBtn = card.querySelector(".btn-start");
    const stopBtn = card.querySelector(".btn-stop");
    const deleteBtn = card.querySelector(".btn-delete");
    const logsBtn = card.querySelector(".btn-logs");
    const logPre = card.querySelector(".plc-log-console");
    const logOpen = openLogPanels.has(inst.id);

    startBtn.disabled = inst.running;
    stopBtn.disabled = !inst.running;
    startBtn.dataset.action = "start-device";
    startBtn.dataset.instanceId = inst.id;
    stopBtn.dataset.action = "stop-device";
    stopBtn.dataset.instanceId = inst.id;
    deleteBtn.dataset.action = "delete-device";
    deleteBtn.dataset.instanceId = inst.id;
    logsBtn.dataset.action = "toggle-logs";
    logsBtn.dataset.instanceId = inst.id;
    logsBtn.textContent = logOpen ? "Hide logs" : "Logs";
    logPre.hidden = !logOpen;
    if (logOpen) {
      refreshLogs(inst.id, logPre);
    }

    renderHmiPanel(inst, card);
  }

  function renderSavedDevices() {
    savedDevicesListEl.innerHTML = "";
    savedDevicesEmptyEl.hidden = savedDevices.length > 0;
    for (const saved of savedDevices) {
      const deviceText = saved.device
        ? `${saved.device.display_name} - ${saved.device.device_class.toUpperCase()}`
        : `${saved.device_type_id} - unavailable`;
      const availability = saved.device
        ? saved.device.implemented
          ? "Ready"
          : "Backend unavailable"
        : "Definition missing";
      const item = document.createElement("article");
      item.className = "saved-item";
      item.innerHTML = `
        <div class="saved-item-main">
          <div class="saved-item-title-row">
            <h3 class="saved-item-title">${escapeHtml(saved.name)}</h3>
            <span class="saved-item-status" data-state="${saved.device?.implemented ? "ready" : "warn"}">${escapeHtml(availability)}</span>
          </div>
          <div class="saved-item-meta">${escapeHtml(deviceText)}</div>
          <div class="saved-item-detail">Launches as ${escapeHtml(saved.config.name || "unnamed")} on ${escapeHtml(saved.config.host || "--")}:${escapeHtml(saved.config.port || "--")}</div>
        </div>
        <div class="saved-item-actions">
          <button class="btn btn-sm btn-primary" data-action="launch-saved" data-saved-id="${saved.id}">Launch</button>
          <button class="btn btn-sm btn-ghost" data-action="edit-saved" data-saved-id="${saved.id}">Edit</button>
          <button class="btn btn-sm btn-danger" data-action="delete-saved" data-saved-id="${saved.id}">Delete</button>
        </div>
      `;
      savedDevicesListEl.appendChild(item);
    }
  }

  function render(list) {
    emptyStateEl.hidden = list.length > 0;

    let running = 0;
    list.forEach((inst) => {
      if (inst.running) running += 1;
    });
    countRunningEl.textContent = running;
    countStoppedEl.textContent = list.length - running;

    const sortedList = [...list].sort((a, b) => a.name.localeCompare(b.name));
    const existingCards = new Map(
      Array.from(fleetEl.querySelectorAll(".card[data-id]")).map((card) => [card.dataset.id, card])
    );
    const nextIds = new Set();

    for (const inst of sortedList) {
      let card = existingCards.get(inst.id);
      if (!card) {
        card = createCardElement();
      }
      updateCard(inst, card);
      fleetEl.appendChild(card);
      nextIds.add(inst.id);
    }

    for (const [id, card] of existingCards.entries()) {
      if (!nextIds.has(id)) {
        card.remove();
      }
    }
  }

  async function refresh() {
    try {
      const { response, payload } = await fetchJson("/api/instances");
      if (!response.ok) return;
      lastList = payload;
      await refreshOpenHmiStatuses(payload);
      render(payload);
      if (!faultOverlay.hidden) {
        const preferredInstanceId = faultInstanceSelect.value;
        populateFaultInstanceOptions(preferredInstanceId);
        if (faultInstanceSelect.value) {
          await refreshFaultStatus(faultInstanceSelect.value);
        } else {
          renderFaultActiveList();
        }
      }
    } catch {
      // Server may be restarting; keep the last render.
    }
  }

  async function saveCurrentConfig() {
    formError.hidden = true;
    let payload;
    try {
      payload = buildInstancePayload({ requireImplemented: false });
    } catch (err) {
      formError.textContent = err.message;
      formError.hidden = false;
      return;
    }
    payload.save_name = saveNameInput.value.trim();
    if (!payload.save_name) {
      formError.textContent = "Enter a saved config name before saving.";
      formError.hidden = false;
      return;
    }

    const savedId = saveIdInput.value.trim();
    const url = savedId ? `/api/saved-devices/${encodeURIComponent(savedId)}` : "/api/saved-devices";
    const method = savedId ? "PUT" : "POST";
    try {
      const { response, payload: json } = await fetchJson(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        formError.textContent = json.error || "Failed to save config.";
        formError.hidden = false;
        return;
      }
      await refreshSavedDevices();
      closeOverlay();
      showPageNotice(
        json.created ? `Saved config "${json.saved_device.name}".` : `Updated saved config "${json.saved_device.name}".`,
        "success"
      );
    } catch (err) {
      formError.textContent = `Network error: ${err.message}`;
      formError.hidden = false;
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    formError.hidden = true;
    let payload;
    try {
      payload = buildInstancePayload({ requireImplemented: true });
    } catch (err) {
      formError.textContent = err.message;
      formError.hidden = false;
      return;
    }

    try {
      const { response, payload: json } = await fetchJson("/api/instances", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        formError.textContent = json.error || "Failed to create device.";
        formError.hidden = false;
        return;
      }
      closeOverlay();
      if (json.warning) {
        showPageNotice(json.warning, "warn");
      }
      refresh();
    } catch (err) {
      formError.textContent = `Network error: ${err.message}`;
      formError.hidden = false;
    }
  });

  saveConfigBtn.addEventListener("click", () => {
    saveCurrentConfig();
  });

  faultForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    faultFormError.hidden = true;
    faultFormError.textContent = "";
    const inst = currentFaultInstance();
    const point = currentFaultPoint();
    const mode = faultModeSelect.value;
    if (!inst || !point || !mode) {
      faultFormError.textContent = "Select an instance, point, and mode.";
      faultFormError.hidden = false;
      return;
    }
    const params = {};
    if (mode === "drift") {
      params.drift_rate_per_sec = parseFloat(faultDriftRateInput.value);
      params.direction = parseFloat(faultDriftDirectionInput.value);
      if (Number.isNaN(params.drift_rate_per_sec) || Number.isNaN(params.direction)) {
        faultFormError.textContent = "Drift rate and direction must be numeric.";
        faultFormError.hidden = false;
        return;
      }
    }
    if (mode === "noise") {
      params.amplitude = parseFloat(faultNoiseAmplitudeInput.value);
      if (Number.isNaN(params.amplitude)) {
        faultFormError.textContent = "Noise amplitude must be numeric.";
        faultFormError.hidden = false;
        return;
      }
    }
    const { response, payload } = await fetchJson(`/api/instances/${inst.id}/fault`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ point: point.id, mode, params }),
    });
    if (!response.ok) {
      faultFormError.textContent = payload.error || "Failed to inject fault.";
      faultFormError.hidden = false;
      return;
    }
    showPageNotice(`Injected ${mode} fault on ${inst.name}:${point.id}.`, "warn");
    setTimeout(() => refreshFaultStatus(inst.id), 300);
  });

  clearSelectedFaultBtn.addEventListener("click", async () => {
    faultFormError.hidden = true;
    faultFormError.textContent = "";
    const inst = currentFaultInstance();
    const point = currentFaultPoint();
    if (!inst || !point) {
      faultFormError.textContent = "Select an instance and point to clear.";
      faultFormError.hidden = false;
      return;
    }
    const { response, payload } = await fetchJson(`/api/instances/${inst.id}/fault/clear`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ point: point.id }),
    });
    if (!response.ok) {
      faultFormError.textContent = payload.error || "Failed to clear fault.";
      faultFormError.hidden = false;
      return;
    }
    showPageNotice(`Cleared fault on ${inst.name}:${point.id}.`, "success");
    setTimeout(() => refreshFaultStatus(inst.id), 300);
  });

  savedDevicesListEl.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const savedId = parseInt(button.dataset.savedId || "", 10);
    const savedDevice = savedDevices.find((entry) => entry.id === savedId);
    if (!savedDevice) return;

    if (button.dataset.action === "launch-saved") {
      const { response, payload } = await fetchJson(`/api/saved-devices/${savedId}/launch`, { method: "POST" });
      if (!response.ok) {
        showPageNotice(payload.error || "Failed to launch saved config.", "error");
        return;
      }
      if (payload.warning) {
        showPageNotice(payload.warning, "warn");
      } else {
        showPageNotice(`Launched "${savedDevice.name}".`, "success");
      }
      await refresh();
      return;
    }

    if (button.dataset.action === "edit-saved") {
      openOverlay({ savedDevice });
      return;
    }

    if (button.dataset.action === "delete-saved") {
      if (!confirm(`Delete saved config "${savedDevice.name}"?`)) return;
      const { response, payload } = await fetchJson(`/api/saved-devices/${savedId}`, { method: "DELETE" });
      if (!response.ok) {
        showPageNotice(payload.error || "Failed to delete saved config.", "error");
        return;
      }
      await refreshSavedDevices();
      showPageNotice(`Deleted saved config "${savedDevice.name}".`, "success");
    }
  });

  fleetEl.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    const instanceId = button.dataset.instanceId;
    const hmiId = button.dataset.hmiId;
    const pointId = button.dataset.pointId;
    if (action === "start-device") {
      await fetchJson(`/api/instances/${instanceId}/start`, { method: "POST" });
      refresh();
      return;
    }
    if (action === "stop-device") {
      await fetchJson(`/api/instances/${instanceId}/stop`, { method: "POST" });
      refresh();
      return;
    }
    if (action === "delete-device") {
      if (!confirm("Delete this device instance? Any attached HMI will also be removed.")) return;
      openLogPanels.delete(instanceId);
      openHmiPanels.delete(instanceId);
      const inst = lastList.find((item) => item.id === instanceId);
      if (inst?.hmi?.id) {
        hmiStatusCache.delete(inst.hmi.id);
        pendingHmiCommands.delete(inst.hmi.id);
        hmiSetpointDrafts.delete(inst.hmi.id);
      }
      await fetchJson(`/api/instances/${instanceId}`, { method: "DELETE" });
      refresh();
      return;
    }
    if (action === "toggle-logs") {
      if (openLogPanels.has(instanceId)) {
        openLogPanels.delete(instanceId);
      } else {
        openLogPanels.add(instanceId);
      }
      render(lastList);
      return;
    }
    if (action === "open-hmi") {
      const inst = lastList.find((item) => item.id === instanceId);
      if (inst) await openHmi(inst);
      return;
    }
    if (action === "close-hmi") {
      closeHmi(instanceId);
      return;
    }
    if (action === "stop-hmi") {
      if (hmiId) await stopHmi(instanceId, hmiId);
      return;
    }
    if (action === "delete-hmi") {
      if (hmiId) await removeHmi(instanceId, hmiId);
      return;
    }
    if (action === "write-toggle") {
      const label = button.textContent.trim();
      await sendHmiCommand(hmiId, pointId, button.dataset.value === "true", label);
    }
  });

  fleetEl.addEventListener("submit", async (event) => {
    const formEl = event.target.closest(".hmi-setpoint-form");
    if (!formEl) return;
    event.preventDefault();
    const hmiId = formEl.dataset.hmiId;
    const pointId = formEl.dataset.pointId;
    const input = formEl.querySelector(".hmi-setpoint-input");
    const value = parseFloat(input.value);
    if (Number.isNaN(value)) {
      alert("Enter a numeric setpoint value.");
      return;
    }
    hmiSetpointDrafts.set(hmiId, { value: input.value, focused: false });
    input.blur();
    await sendHmiCommand(hmiId, pointId, value, `Apply ${pointId}`);
  });

  fleetEl.addEventListener("focusin", (event) => {
    const input = event.target.closest(".hmi-setpoint-input");
    if (!(input instanceof HTMLInputElement)) return;
    hmiSetpointDrafts.set(input.dataset.hmiId, {
      value: input.value,
      focused: true,
      selectionStart: input.selectionStart ?? input.value.length,
      selectionEnd: input.selectionEnd ?? input.value.length,
    });
  });

  fleetEl.addEventListener("input", (event) => {
    const input = event.target.closest(".hmi-setpoint-input");
    if (!(input instanceof HTMLInputElement)) return;
    hmiSetpointDrafts.set(input.dataset.hmiId, {
      value: input.value,
      focused: true,
      selectionStart: input.selectionStart ?? input.value.length,
      selectionEnd: input.selectionEnd ?? input.value.length,
    });
  });

  fleetEl.addEventListener("focusout", (event) => {
    const input = event.target.closest(".hmi-setpoint-input");
    if (!(input instanceof HTMLInputElement)) return;
    hmiSetpointDrafts.set(input.dataset.hmiId, {
      value: input.value,
      focused: false,
    });
  });

  if (openFaultLabBtn) {
    openFaultLabBtn.addEventListener("click", () => {
      openFaultOverlay();
    });
  }
  openButtons.forEach((button) => button.addEventListener("click", () => openOverlay()));
  closeButtons.forEach((button) => button.addEventListener("click", closeOverlay));
  closeFaultButtons.forEach((button) => button.addEventListener("click", closeFaultOverlay));
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) closeOverlay();
  });
  faultOverlay.addEventListener("click", (event) => {
    if (event.target === faultOverlay) closeFaultOverlay();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !overlay.hidden) closeOverlay();
    if (event.key === "Escape" && !faultOverlay.hidden) closeFaultOverlay();
  });
  deviceTypeSelect.addEventListener("change", () => syncSelectedDeviceType());
  hostSelect.addEventListener("change", () => syncHostInputVisibility());
  faultInstanceSelect.addEventListener("change", async () => {
    syncFaultPointOptions();
    if (faultInstanceSelect.value) {
      await refreshFaultStatus(faultInstanceSelect.value);
    } else {
      renderFaultActiveList();
    }
  });
  faultPointSelect.addEventListener("change", () => syncFaultModeOptions());
  faultModeSelect.addEventListener("change", () => syncFaultParamVisibility());
  overrideEnabledEl.addEventListener("change", () => {
    syncAdvancedVisibility();
    if (!overrideEnabledEl.checked) {
      setOverrideFields(currentDeviceType());
    }
  });
  portInput.addEventListener("input", checkPrivilegedPort);

  setInterval(() => {
    refresh();
  }, STATUS_POLL_MS);

  syncAdvancedVisibility();
  Promise.all([loadDeviceTypes(), loadHostAddresses(), refreshSavedDevices()])
    .then(() => {
      if (deviceErrors.length > 0) {
        showPageNotice(`Loaded device definitions with ${deviceErrors.length} validation warning(s).`, "warn");
      }
      return refresh();
    })
    .catch((err) => {
      formError.textContent = `Failed to load device definitions: ${err.message}`;
      formError.hidden = false;
      protocolDisplayEl.textContent = "UNAVAILABLE";
      protocolDetailEl.textContent = "Device definition registry load failed";
      deviceTypeDetailEl.textContent = "Check /api/device-types and server logs.";
      refresh();
    });
})();
