async function runTopology() {
    const btn = document.getElementById('topoBtn');
    btn.disabled = true;

    const res = await fetch('/run-topology', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ options: {
            traceroute: document.getElementById('optTraceroute').checked,
            snmp:       document.getElementById('optSnmp').checked,
            passive:    document.getElementById('optPassive').checked,
            mdns:       document.getElementById('optMdns').checked,
            ssdp:       document.getElementById('optSsdp').checked,
            netbios:    document.getElementById('optNetbios').checked,
            banners:    document.getElementById('optBanners').checked,
        }})
    });

    if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        toast('✗ ' + (data.error || 'Topology failed'));
        btn.disabled = false;
        return;
    }

    toast('⬡ Topology discovery started');
    document.getElementById('topoProgressBar').classList.add('show');

    if (_topoPoller) clearInterval(_topoPoller);
    _topoPoller = setInterval(pollTopoStatus, 1500);
}

async function pollTopoStatus() {
    try {
        const res  = await fetch('/topology-status');
        const data = await res.json();
        const fill  = document.getElementById('topoProgressFill');
        const label = document.getElementById('topoPhaseLabel');
        const btn   = document.getElementById('topoBtn');

        fill.style.width = data.progress + '%';
        const phaseNames = {
            init:         'Initializing',
            traceroute:   'Phase 1: Traceroute',
            snmp:         'Phase 2: SNMP',
            passive_sniff:'Phase 3: Passive Sniff (LLDP+DHCP)',
            mdns:         'Enrichment: mDNS/Bonjour',
            ssdp:         'Enrichment: SSDP/UPnP',
            netbios:      'Enrichment: NetBIOS',
            fingerprint:  'Enrichment: Port Fingerprint',
            build_graph:  'Building topology graph',
        };
        const name = phaseNames[data.phase] || data.phase || 'Running';
        label.textContent = 'TOPOLOGY: ' + name + ' (' + data.progress + '%)';

        if (data.status === 'done') {
            clearInterval(_topoPoller);
            btn.disabled = false;
            document.getElementById('topoProgressBar').classList.remove('show');
            toast('✓ Topology complete — reloading map');
            if (data.warnings && data.warnings.length) {
                const w = data.warnings.slice(0, 2).join(' · ');
                const extra = data.warnings.length > 2 ? '…' : '';
                setTimeout(() => toast('⚠ ' + w + extra), 400);
            }
            setTimeout(() => runScan(), 800);
        } else if (data.status === 'error') {
            clearInterval(_topoPoller);
            btn.disabled = false;
            document.getElementById('topoProgressBar').classList.remove('show');
            toast('✗ Topology error: ' + data.error);
        }
    } catch(e) {
        // server temporarily unavailable, keep polling
    }
}
