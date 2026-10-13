// AI-SHIELD Core SOC Dashboard Logic

async function updateSystemTelemetry() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    
    // Update monitor badge
    const monTxt = document.getElementById('txt-monitor-status');
    const monDot = document.querySelector('#badge-monitor .status-dot');
    if (monTxt && monDot) {
      if (data.monitoring.running) {
        monTxt.innerText = `MONITORING: ${data.monitoring.mode.toUpperCase()}`;
        monDot.className = 'status-dot dot-green pulse';
      } else {
        monTxt.innerText = 'MONITOR: IDLE';
        monDot.className = 'status-dot dot-amber';
      }
    }
    
    // Update IPS mode badge
    const ipsTxt = document.getElementById('txt-ips-mode');
    const ipsDot = document.querySelector('#badge-ips .status-dot');
    if (ipsTxt && ipsDot) {
      ipsTxt.innerText = `IPS: ${data.prevention_mode.toUpperCase()}`;
      if (data.prevention_mode === 'Enabled') {
        ipsDot.className = 'status-dot dot-red pulse';
      } else if (data.prevention_mode === 'Alert Only') {
        ipsDot.className = 'status-dot dot-blue';
      } else {
        ipsDot.className = 'status-dot dot-amber';
      }
    }
  } catch (err) {
    console.warn("Failed to fetch system telemetry:", err);
  }
}

// Global quick actions
async function startMonitoring(mode = 'simulation') {
  try {
    const res = await fetch('/api/monitor/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({mode: mode})
    });
    const data = await res.json();
    updateSystemTelemetry();
    return data;
  } catch (err) {
    alert("Error starting monitor: " + err);
  }
}

async function stopMonitoring() {
  try {
    const res = await fetch('/api/monitor/stop', {method: 'POST'});
    const data = await res.json();
    updateSystemTelemetry();
    return data;
  } catch (err) {
    alert("Error stopping monitor: " + err);
  }
}

// Auto update status every 3 seconds
setInterval(updateSystemTelemetry, 3000);
document.addEventListener('DOMContentLoaded', updateSystemTelemetry);
