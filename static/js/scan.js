function parseSubnetInput() {
    const raw = document.getElementById('multiSubnetInput')?.value || '';
    return [...new Set(raw.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean))];
}

async function runScan() {
    const overlay = document.getElementById('scanOverlay');
    const btn     = document.getElementById('rescanBtn');
    const manualSubnets = parseSubnetInput();
    const useMulti = manualSubnets.length > 1;
    document.getElementById('scanLabel').textContent = 'Scanning Network';
    document.getElementById('scanSub').textContent   = useMulti
        ? `Scanning ${manualSubnets.length} subnets sequentially...`
        : 'ARP + ping sweep in progress...';
    document.getElementById('scanProgressWrap').style.display = 'none';
    overlay.style.display = 'flex';
    btn.disabled = true;
    nodes.forEach(n => n.el.remove());
    nodes = []; topoEdges = [];
    closePanel();

    let scanData, savedData, topoData;
    try {
        const scanPromise = useMulti
            ? fetch('/scan-multi', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ subnets: manualSubnets })
            })
            : fetch('/scan');
        const [scanRes, savedRes, topoRes] = await Promise.all([
            scanPromise, fetch('/devices'), fetch('/topology')
        ]);
        if (!scanRes.ok || !savedRes.ok || !topoRes.ok) {
            throw new Error('One or more API requests failed');
        }
        scanData  = await scanRes.json();
        savedData = await savedRes.json();
        topoData  = await topoRes.json();
    } catch (e) {
        overlay.style.display = 'none';
        btn.disabled = false;
        toast('✗ Scan failed');
        return;
    }

    const cleanDevices = scanData.devices.filter(d => !isNoiseDevice(d));
    const tagged = cleanDevices.map(d => ({
        ...d, randomized: isMacRandomized(d.mac)
    }));

    if (useMulti) {
        const requested = Array.isArray(scanData.subnets_requested)
            ? scanData.subnets_requested
            : manualSubnets;
        document.getElementById('hSubnet').textContent = `${requested.length} subnets`;
    } else {
        document.getElementById('hSubnet').textContent = scanData.subnet + '.0/24';
    }
    document.getElementById('hCount').textContent   = tagged.length;
    document.getElementById('hRandom').textContent  = tagged.filter(d => d.randomized).length;

    const legendEnrich = document.getElementById('legendEnrich');
    if (topoData.edges?.length > 0) {
        topoEdges = topoData.edges;
        document.getElementById('legendBox').style.display = 'flex';
        const meta = topoData.meta || {};
        const methods = [];
        if (meta.has_lldp)       methods.push('LLDP');
        if (meta.has_snmp)       methods.push('SNMP');
        if (meta.has_traceroute) methods.push('L3');
        if (meta.has_mdns)       methods.push('mDNS');
        if (meta.has_ssdp)       methods.push('SSDP');
        if (meta.has_dhcp_fp)    methods.push('DHCP');
        document.getElementById('hTopo').textContent = methods.length
            ? methods.join('+') : 'inferred';
        const enrich = [];
        if (meta.has_ssdp)    enrich.push('SSDP');
        if (meta.has_dhcp_fp) enrich.push('DHCP FP');
        if (meta.has_mdns)    enrich.push('mDNS');
        if (enrich.length) {
            legendEnrich.textContent = 'ENRICH: ' + enrich.join(' · ');
            legendEnrich.style.display = 'block';
        } else {
            legendEnrich.style.display = 'none';
        }
    } else {
        document.getElementById('hTopo').textContent = '—';
        document.getElementById('legendBox').style.display = 'none';
        legendEnrich.style.display = 'none';
    }

    devices = tagged.map(scanned => {
        const saved = savedData.find(s =>
            (scanned.mac && s.mac === scanned.mac) ||
            (!scanned.mac && s.ip === scanned.ip)
        );
        const topoNode = (topoData.nodes || []).find(n => n.ip === scanned.ip);
        const base = saved
            ? { ...scanned, ...saved, ip: scanned.ip, randomized: scanned.randomized }
            : { ...scanned, type: 'other', name: '', room: '', notes: '' };
        if (topoNode) {
            for (const f of ['mdns_services','ssdp_server','opt55_os','open_ports','sysinfo']) {
                if (topoNode[f] && !base[f]) base[f] = topoNode[f];
            }
            if (base.type === 'other' && topoNode.type !== 'other') base.type = topoNode.type;
        }
        return base;
    });

    if (devices.length === 0) {
        document.getElementById('emptyState').style.display = 'flex';
    } else {
        document.getElementById('emptyState').style.display = 'none';
        layoutNodes(devices);
    }

    const saveAllRes = await fetch('/save-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(devices)
    });
    if (!saveAllRes.ok) {
        toast('⚠ Inventory sync failed');
    }
    if (useMulti && Array.isArray(scanData.subnet_results)) {
        const problems = scanData.subnet_results
            .filter(s => Array.isArray(s.errors) && s.errors.length)
            .map(s => `${s.subnet}: ${s.errors[0]}`);
        if (problems.length) {
            toast('⚠ ' + problems.slice(0, 2).join(' · ') + (problems.length > 2 ? '…' : ''));
        }
    }

    overlay.style.display = 'none';
    btn.disabled = false;
}
