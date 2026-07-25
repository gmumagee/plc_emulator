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
  const fleetEl = document.getElementById("fleet");
  const emptyStateEl = document.getElementById("emptyState");
  const cardTemplate = document.getElementById("cardTemplate");
  const countRunningEl = document.getElementById("countRunning");
  const countStoppedEl = document.getElementById("countStopped");

  const overlay = document.getElementById("overlay");
  const form = document.getElementById("newInstanceForm");
  const formError = document.getElementById("formError");
  const privilegedNote = document.getElementById("privilegedNote");
  const authbindStatusEl = document.getElementById("authbindStatus");
  const portInput = document.getElementById("f-port");
  const plcTypeSelect = document.getElementById("f-plc-type");
  const plcTypeAvailabilityEl = document.getElementById("plcTypeAvailability");
  const plcTypeDetailEl = document.getElementById("plcTypeDetail");
  const protocolDisplayEl = document.getElementById("protocolDisplay");
  const protocolDetailEl = document.getElementById("protocolDetail");
  const protocolWarningEl = document.getElementById("protocolWarning");
  const overrideEnabledEl = document.getElementById("f-override-enabled");
  const advancedPanelEl = document.getElementById("advancedPanel");
  const vendorInput = document.getElementById("f-vendor");
  const modelInput = document.getElementById("f-model");
  const productInput = document.getElementById("f-product");

  const openButtons = [document.getElementById("newInstanceBtn"), document.getElementById("emptyStateBtn")];
  const closeButtons = [document.getElementById("closePanelBtn"), document.getElementById("cancelBtn")];

  let authbindAvailable = null;
  let plcTypes = {};
  let plcTypeEntries = [];
  let lastList = [];

  const openLogPanels = new Set();
  const openHmiPanels = new Set();
  const hmiStatusCache = new Map();
  const pendingHmiCommands = new Map();
  const hmiSetpointDrafts = new Map();

  function protocolLabel(protocol) {
    return PROTOCOL_LABELS[protocol] || String(protocol || "modbus").toUpperCase();
  }

  function sortPlcTypes(payload) {
    return Object.entries(payload).sort(([, left], [, right]) => {
      const vendorCompare = left.vendor.localeCompare(right.vendor);
      if (vendorCompare !== 0) return vendorCompare;
      return left.model.localeCompare(right.model);
    });
  }

  function currentPlcType() {
    return plcTypes[plcTypeSelect.value] || null;
  }

  function setOverrideFields(plcType) {
    if (!plcType) return;
    vendorInput.value = plcType.vendor;
    modelInput.value = plcType.model;
    productInput.value = plcType.product_code;
  }

  function syncAdvancedVisibility() {
    const enabled = overrideEnabledEl.checked;
    advancedPanelEl.hidden = !enabled;
    vendorInput.disabled = !enabled;
    modelInput.disabled = !enabled;
    productInput.disabled = !enabled;
  }

  function syncSelectedPlcType({ preservePort = false } = {}) {
    const plcType = currentPlcType();
    if (!plcType) {
      protocolDisplayEl.textContent = "UNAVAILABLE";
      protocolDetailEl.textContent = "No PLC type presets loaded";
      protocolWarningEl.hidden = false;
      protocolWarningEl.textContent = "The PLC type registry is empty or failed to load.";
      plcTypeAvailabilityEl.textContent = "Unavailable";
      plcTypeAvailabilityEl.dataset.state = "unavailable";
      plcTypeDetailEl.textContent = "No preset data available.";
      return;
    }

    protocolDisplayEl.textContent = protocolLabel(plcType.protocol);
    protocolDetailEl.textContent = `Default port ${plcType.default_port}`;
    protocolWarningEl.hidden = plcType.implemented;
    protocolWarningEl.textContent = plcType.implemented
      ? ""
      : `${protocolLabel(plcType.protocol)} is mapped for this PLC type, but that backend is not implemented in this build yet.`;
    plcTypeAvailabilityEl.textContent = plcType.implemented ? "Available" : "Unavailable";
    plcTypeAvailabilityEl.dataset.state = plcType.implemented ? "available" : "unavailable";
    plcTypeDetailEl.textContent = `Vendor "${plcType.vendor}" • Model "${plcType.model}" • Product code "${plcType.product_code}"`;
    if (!preservePort) {
      portInput.value = plcType.default_port;
    }
    setOverrideFields(plcType);
    checkPrivilegedPort();
  }

  function populatePlcTypeOptions(preferredType) {
    plcTypeEntries = sortPlcTypes(plcTypes);
    plcTypeSelect.innerHTML = "";

    for (const [key, plcType] of plcTypeEntries) {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = `${plcType.vendor} ${plcType.model}`;
      plcTypeSelect.appendChild(option);
    }

    const firstType = plcTypeEntries[0]?.[0] || "";
    plcTypeSelect.value = preferredType && plcTypes[preferredType] ? preferredType : firstType;
    syncSelectedPlcType();
  }

  async function fetchJson(url, options) {
    const response = await fetch(url, options);
    let payload = {};
    try {
      payload = await response.json();
    } catch {
      payload = {};
    }
    return { response, payload };
  }

  async function loadPlcTypes() {
    const { response, payload } = await fetchJson("/api/plc-types");
    if (!response.ok) {
      throw new Error(`Failed to load PLC types (${response.status})`);
    }
    plcTypes = payload;
    populatePlcTypeOptions();
  }

  function openOverlay() {
    overlay.hidden = false;
    document.getElementById("f-name").focus();
    checkPrivilegedPort();
  }

  function closeOverlay() {
    overlay.hidden = true;
    form.reset();
    syncAdvancedVisibility();
    populatePlcTypeOptions();
    formError.hidden = true;
    document.getElementById("f-autostart").checked = true;
  }

  openButtons.forEach((button) => button.addEventListener("click", openOverlay));
  closeButtons.forEach((button) => button.addEventListener("click", closeOverlay));
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) closeOverlay();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !overlay.hidden) closeOverlay();
  });
  plcTypeSelect.addEventListener("change", () => syncSelectedPlcType());
  overrideEnabledEl.addEventListener("change", () => {
    syncAdvancedVisibility();
    if (!overrideEnabledEl.checked) {
      setOverrideFields(currentPlcType());
    }
  });

  async function checkPrivilegedPort() {
    const port = parseInt(portInput.value, 10);
    if (!port || port >= 1024) {
      privilegedNote.hidden = true;
      return;
    }
    if (authbindAvailable === null) {
      try {
        const { payload } = await fetchJson("/api/authbind-status");
        authbindAvailable = payload.available;
      } catch {
        authbindAvailable = false;
      }
    }
    authbindStatusEl.textContent = authbindAvailable
      ? "authbind is installed - this should work."
      : "authbind was not found on this host - launch may fail unless run as root.";
    privilegedNote.hidden = false;
  }

  portInput.addEventListener("input", checkPrivilegedPort);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    formError.hidden = true;

    const payload = {
      name: document.getElementById("f-name").value.trim(),
      host: document.getElementById("f-host").value.trim(),
      port: parseInt(document.getElementById("f-port").value, 10),
      unit_id: parseInt(document.getElementById("f-unit").value, 10),
      plc_type: plcTypeSelect.value || null,
      verbose: document.getElementById("f-verbose").checked,
      autostart: document.getElementById("f-autostart").checked,
    };

    const selectedType = currentPlcType();
    if (!selectedType) {
      formError.textContent = "No PLC type preset is available.";
      formError.hidden = false;
      return;
    }
    if (!selectedType.implemented) {
      formError.textContent = `${protocolLabel(selectedType.protocol)} is not implemented in this build yet.`;
      formError.hidden = false;
      return;
    }

    if (overrideEnabledEl.checked) {
      payload.vendor = vendorInput.value.trim() || selectedType.vendor;
      payload.model = modelInput.value.trim() || selectedType.model;
      payload.product_code = productInput.value.trim() || selectedType.product_code;
    }

    try {
      const { response, payload: json } = await fetchJson("/api/instances", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        formError.textContent = json.error || "Failed to create instance.";
        formError.hidden = false;
        return;
      }
      if (json.warning) {
        formError.textContent = json.warning;
        formError.hidden = false;
      }
      closeOverlay();
      refresh();
    } catch (err) {
      formError.textContent = `Network error: ${err.message}`;
      formError.hidden = false;
    }
  });

  async function startInstance(id) {
    await fetch(`/api/instances/${id}/start`, { method: "POST" });
    refresh();
  }

  async function stopInstance(id) {
    await fetch(`/api/instances/${id}/stop`, { method: "POST" });
    refresh();
  }

  async function deleteInstance(id) {
    if (!confirm("Delete this PLC instance? This stops it and removes its config. Any attached HMI will also be removed.")) return;
    openLogPanels.delete(id);
    openHmiPanels.delete(id);
    const inst = lastList.find((item) => item.id === id);
    if (inst?.hmi?.id) {
      hmiStatusCache.delete(inst.hmi.id);
      pendingHmiCommands.delete(inst.hmi.id);
      hmiSetpointDrafts.delete(inst.hmi.id);
    }
    await fetch(`/api/instances/${id}`, { method: "DELETE" });
    refresh();
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function colorizeLogLine(line) {
    if (/\bWARNING\b/.test(line)) return `<span class="lvl-warning">${escapeHtml(line)}</span>`;
    if (/\bERROR\b|Traceback/.test(line)) return `<span class="lvl-error">${escapeHtml(line)}</span>`;
    if (/\bINFO\b/.test(line)) return `<span class="lvl-info">${escapeHtml(line)}</span>`;
    return escapeHtml(line);
  }

  async function refreshLogs(id, preEl) {
    try {
      const { payload } = await fetchJson(`/api/instances/${id}/logs?lines=200`);
      const atBottom = preEl.scrollTop + preEl.clientHeight >= preEl.scrollHeight - 10;
      preEl.innerHTML = (payload.log || "(no log output yet)")
        .split("\n")
        .map(colorizeLogLine)
        .join("\n");
      if (atBottom) preEl.scrollTop = preEl.scrollHeight;
    } catch {
      // Ignore transient errors during restart.
    }
  }

  function formatClock(ts) {
    if (!ts) return "--:--:--";
    return new Date(ts * 1000).toLocaleTimeString();
  }

  function setControlState(button, isCurrent) {
    button.dataset.current = isCurrent ? "true" : "false";
    button.setAttribute("aria-pressed", isCurrent ? "true" : "false");
  }

  function captureActiveSetpointEditor() {
    const active = document.activeElement;
    if (!(active instanceof HTMLInputElement) || !active.classList.contains("hmi-setpoint-input")) {
      return null;
    }
    const hmiId = active.dataset.hmiId;
    if (!hmiId) return null;
    const snapshot = {
      hmiId,
      value: active.value,
      selectionStart: active.selectionStart ?? active.value.length,
      selectionEnd: active.selectionEnd ?? active.value.length,
    };
    hmiSetpointDrafts.set(hmiId, {
      value: snapshot.value,
      focused: true,
      selectionStart: snapshot.selectionStart,
      selectionEnd: snapshot.selectionEnd,
    });
    return snapshot;
  }

  function restoreActiveSetpointEditor(activeEditor) {
    if (!activeEditor?.hmiId) return;
    const selector = `.hmi-setpoint-input[data-hmi-id="${activeEditor.hmiId}"]`;
    const input = fleetEl.querySelector(selector);
    if (!(input instanceof HTMLInputElement)) return;
    input.focus();
    input.setSelectionRange(activeEditor.selectionStart, activeEditor.selectionEnd);
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
    await fetch(`/api/hmi/${hmiId}/stop`, { method: "POST" });
    pendingHmiCommands.delete(hmiId);
    await refresh();
    openHmiPanels.add(instId);
    render(lastList);
  }

  async function removeHmi(instId, hmiId) {
    if (!confirm("Delete this HMI client?")) return;
    await fetch(`/api/hmi/${hmiId}`, { method: "DELETE" });
    pendingHmiCommands.delete(hmiId);
    hmiStatusCache.delete(hmiId);
    hmiSetpointDrafts.delete(hmiId);
    openHmiPanels.delete(instId);
    refresh();
  }

  function commandLabel(action, value) {
    if (action === "set_pump") return value ? "Start pump" : "Stop pump";
    if (action === "set_valve") return value ? "Open valve" : "Close valve";
    if (action === "set_setpoint") return `Set level SP to ${value}%`;
    return action;
  }

  async function sendHmiCommand(hmiId, action, value) {
    const { response, payload } = await fetchJson(`/api/hmi/${hmiId}/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, value }),
    });
    if (!response.ok) {
      alert(payload.error || "Failed to send HMI command.");
      return;
    }
    pendingHmiCommands.set(hmiId, {
      commandId: payload.command_id,
      label: commandLabel(action, value),
      sentAt: Date.now(),
    });
    render(lastList);
    setTimeout(() => refresh(), 400);
  }

  function renderHmiEvents(preEl, status) {
    const events = status?.recent_events || [];
    if (events.length === 0) {
      preEl.textContent = "(no HMI events yet)";
      return;
    }
    preEl.innerHTML = events
      .map((event) => {
        const line = `[${formatClock(event.ts)}] ${event.message}`;
        if (event.type === "error") return `<span class="lvl-error">${escapeHtml(line)}</span>`;
        if (event.type === "command") return `<span class="lvl-info">${escapeHtml(line)}</span>`;
        return escapeHtml(line);
      })
      .join("\n");
  }

  function renderHmiPanel(inst, card) {
    const panel = card.querySelector(".hmi-panel");
    const panelOpen = openHmiPanels.has(inst.id);
    panel.hidden = !panelOpen;

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
    openBtn.addEventListener("click", () => openHmi(inst));

    if (!panelOpen) return;

    const hmi = inst.hmi;
    const bundle = hmi?.id ? hmiStatusCache.get(hmi.id) : null;
    const status = bundle?.status || null;
    const snapshot = status?.snapshot || null;
    const controlsDisabled = !hmi?.running || !hmi.supported;

    panel.querySelector(".hmi-panel-subtitle").textContent = hmi
      ? `${protocolLabel(hmi.protocol)} client polling ${hmi.host}:${hmi.port} every ${hmi.poll_interval.toFixed(1)}s`
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
    if (!hmi) {
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
      bannerEl.textContent = "Waiting for target PLC or first poll result...";
      bannerEl.dataset.state = "warn";
    } else {
      bannerEl.hidden = false;
      bannerEl.textContent = `Last poll ${formatClock(status.last_poll_ts)} over ${protocolLabel(hmi.protocol)}.`;
      bannerEl.dataset.state = "info";
    }

    const levelPct = Math.max(0, Math.min(100, snapshot?.tank_level_pct ?? 0));
    panel.querySelector(".tank-gauge-fill").style.height = `${levelPct}%`;
    panel.querySelector(".tank-gauge-value").textContent = snapshot ? `${snapshot.tank_level_pct.toFixed(1)}%` : "--.-%";
    panel.querySelector(".hmi-flow").textContent = snapshot ? snapshot.flow_rate.toFixed(1) : "--.-";
    panel.querySelector(".hmi-setpoint").textContent = snapshot ? `${snapshot.level_setpoint_pct.toFixed(1)}%` : "--.-%";
    panel.querySelector(".hmi-pump").textContent = snapshot?.pump_run ? "RUNNING" : "STOPPED";
    panel.querySelector(".hmi-valve").textContent = snapshot?.valve_open ? "OPEN" : "CLOSED";
    panel.querySelector(".hmi-alarm-word").textContent = snapshot ? String(snapshot.alarm_word) : "0";
    panel.querySelector(".hmi-uptime").textContent = snapshot ? `${snapshot.uptime_s}s` : "0s";
    panel.querySelector(".alarm-high").dataset.active = snapshot?.level_high ? "true" : "false";
    panel.querySelector(".alarm-low").dataset.active = snapshot?.level_low ? "true" : "false";

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
    const closeBtn = panel.querySelector(".btn-hmi-close");
    const deleteBtn = panel.querySelector(".btn-hmi-delete");
    stopBtn.disabled = !hmi?.running;
    stopBtn.addEventListener("click", () => {
      if (hmi) stopHmi(inst.id, hmi.id);
    });
    closeBtn.addEventListener("click", () => closeHmi(inst.id));
    if (deleteBtn) {
      deleteBtn.addEventListener("click", () => {
        if (hmi) removeHmi(inst.id, hmi.id);
      });
    }

    const commandButtons = [
      [".btn-hmi-pump-on", () => hmi && sendHmiCommand(hmi.id, "set_pump", true)],
      [".btn-hmi-pump-off", () => hmi && sendHmiCommand(hmi.id, "set_pump", false)],
      [".btn-hmi-valve-open", () => hmi && sendHmiCommand(hmi.id, "set_valve", true)],
      [".btn-hmi-valve-close", () => hmi && sendHmiCommand(hmi.id, "set_valve", false)],
    ];
    commandButtons.forEach(([selector, handler]) => {
      const button = panel.querySelector(selector);
      button.disabled = controlsDisabled;
      button.addEventListener("click", handler);
    });

    setControlState(panel.querySelector(".btn-hmi-pump-on"), Boolean(snapshot?.pump_run));
    setControlState(panel.querySelector(".btn-hmi-pump-off"), snapshot ? !snapshot.pump_run : false);
    setControlState(panel.querySelector(".btn-hmi-valve-open"), Boolean(snapshot?.valve_open));
    setControlState(panel.querySelector(".btn-hmi-valve-close"), snapshot ? !snapshot.valve_open : false);

    const setpointForm = panel.querySelector(".hmi-setpoint-form");
    const setpointInput = panel.querySelector(".hmi-setpoint-input");
    if (hmi?.id) {
      setpointInput.dataset.hmiId = hmi.id;
    }
    setpointInput.disabled = controlsDisabled;
    const draftState = hmi?.id ? hmiSetpointDrafts.get(hmi.id) : null;
    if (draftState?.focused) {
      setpointInput.value = draftState.value;
    } else if (snapshot) {
      const polledValue = snapshot.level_setpoint_pct.toFixed(1);
      setpointInput.value = polledValue;
      if (hmi?.id) {
        hmiSetpointDrafts.set(hmi.id, { value: polledValue, focused: false });
      }
    } else if (draftState?.value) {
      setpointInput.value = draftState.value;
    } else {
      setpointInput.value = "";
    }
    setpointInput.placeholder = snapshot ? snapshot.level_setpoint_pct.toFixed(1) : "50.0";
    setpointInput.addEventListener("focus", () => {
      if (!hmi?.id) return;
      hmiSetpointDrafts.set(hmi.id, {
        value: setpointInput.value,
        focused: true,
        selectionStart: setpointInput.selectionStart ?? setpointInput.value.length,
        selectionEnd: setpointInput.selectionEnd ?? setpointInput.value.length,
      });
    });
    setpointInput.addEventListener("input", () => {
      if (!hmi?.id) return;
      hmiSetpointDrafts.set(hmi.id, {
        value: setpointInput.value,
        focused: true,
        selectionStart: setpointInput.selectionStart ?? setpointInput.value.length,
        selectionEnd: setpointInput.selectionEnd ?? setpointInput.value.length,
      });
    });
    setpointInput.addEventListener("blur", () => {
      if (!hmi?.id) return;
      hmiSetpointDrafts.set(hmi.id, {
        value: setpointInput.value,
        focused: false,
      });
    });
    setpointForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!hmi) return;
      const value = parseFloat(setpointInput.value);
      if (Number.isNaN(value)) {
        alert("Enter a numeric setpoint between 0 and 100.");
        return;
      }
      hmiSetpointDrafts.set(hmi.id, { value: setpointInput.value, focused: false });
      setpointInput.blur();
      sendHmiCommand(hmi.id, "set_setpoint", value);
    });

    renderHmiEvents(panel.querySelector(".hmi-log-console"), status);
  }

  function render(list) {
    const activeEditor = captureActiveSetpointEditor();
    fleetEl.innerHTML = "";
    emptyStateEl.hidden = list.length > 0;

    let running = 0;
    list.forEach((inst) => {
      if (inst.running) running += 1;
    });
    countRunningEl.textContent = running;
    countStoppedEl.textContent = list.length - running;

    list.sort((a, b) => a.name.localeCompare(b.name));

    for (const inst of list) {
      const node = cardTemplate.content.cloneNode(true);
      const card = node.querySelector(".card");
      card.dataset.id = inst.id;
      card.dataset.running = String(inst.running);

      node.querySelector(".card-name").textContent = inst.name;
      node.querySelector(".card-subtitle").textContent = `${inst.vendor} / ${inst.model}`;
      node.querySelector(".protocol-tag").textContent = protocolLabel(inst.protocol);
      node.querySelector(".status-label").textContent = inst.running ? "RUNNING" : "STOPPED";
      node.querySelector(".readout-address").textContent = `${inst.host}:${inst.port}`;
      node.querySelector(".readout-unit").textContent = inst.unit_id;
      node.querySelector(".readout-pid").textContent = inst.pid || "-";

      const startBtn = node.querySelector(".btn-start");
      const stopBtn = node.querySelector(".btn-stop");
      startBtn.disabled = inst.running;
      stopBtn.disabled = !inst.running;
      startBtn.addEventListener("click", () => startInstance(inst.id));
      stopBtn.addEventListener("click", () => stopInstance(inst.id));
      node.querySelector(".btn-delete").addEventListener("click", () => deleteInstance(inst.id));

      const logsBtn = node.querySelector(".btn-logs");
      const logPre = node.querySelector(".plc-log-console");
      const isOpen = openLogPanels.has(inst.id);
      logPre.hidden = !isOpen;
      logsBtn.textContent = isOpen ? "Hide logs" : "Logs";
      logsBtn.addEventListener("click", () => {
        if (openLogPanels.has(inst.id)) {
          openLogPanels.delete(inst.id);
        } else {
          openLogPanels.add(inst.id);
          refreshLogs(inst.id, logPre);
        }
        render(lastList);
      });
      if (isOpen) refreshLogs(inst.id, logPre);

      renderHmiPanel(inst, node);
      fleetEl.appendChild(node);
    }
    restoreActiveSetpointEditor(activeEditor);
  }

  async function refresh() {
    try {
      const { response, payload } = await fetchJson("/api/instances");
      if (!response.ok) return;
      lastList = payload;
      await refreshOpenHmiStatuses(payload);
      render(payload);
    } catch {
      // Server may be restarting; keep the last known render.
    }
  }

  setInterval(() => {
    refresh();
  }, STATUS_POLL_MS);

  syncAdvancedVisibility();
  loadPlcTypes()
    .then(() => refresh())
    .catch((err) => {
      formError.textContent = `Failed to load PLC types: ${err.message}`;
      formError.hidden = false;
      protocolDisplayEl.textContent = "UNAVAILABLE";
      protocolDetailEl.textContent = "PLC type registry load failed";
      plcTypeDetailEl.textContent = "Check /api/plc-types and server logs.";
      refresh();
    });
})();
