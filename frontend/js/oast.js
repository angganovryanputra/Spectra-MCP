/**
 * Spectra / AetherGate - OAST (Out-of-Band Application Security Testing) Component
 */

window.OastModule = {
  data() {
    return {
      oastEvents: [],
      latestOastTokenData: null,
      oastVulnTypeInput: 'BLIND_SSRF',
      oastDescriptionInput: 'AI Agent Blind Vulnerability Probe',
      isGeneratingOast: false,
      oastSearchQuery: '',
      oastProtocols: { http: { active: true }, dns: { active: false }, ldap: { active: false } }
    };
  },

  methods: {
    async fetchProtocolsStatus() {
      try {
        const resp = await fetch('/api/oast/protocols/status');
        if (resp.ok) {
          this.oastProtocols = await resp.json();
        }
      } catch (err) {
        console.error('Failed to fetch protocol status:', err);
      }
    },

    async fetchOastEvents() {
      await this.fetchProtocolsStatus();
      const proj = this.selectedProject || 'default';
      try {
        const resp = await fetch(`/api/oast/events?project=${encodeURIComponent(proj)}&limit=100`);
        if (resp.ok) {
          const data = await resp.json();
          this.oastEvents = data.events || [];
          this.$nextTick(() => {
            if (window.lucide) lucide.createIcons();
          });
        }
      } catch (err) {
        console.error('Failed to fetch OAST events:', err);
      }
    },

    async generateNewOastToken() {
      this.isGeneratingOast = true;
      const proj = this.selectedProject === 'ALL' ? 'default' : this.selectedProject;
      try {
        const resp = await fetch('/api/oast/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            project: proj,
            vuln_type: this.oastVulnTypeInput,
            description: this.oastDescriptionInput
          })
        });
        if (resp.ok) {
          this.latestOastTokenData = await resp.json();
          this.showToast({
            title: 'OAST Token Generated',
            message: `Token ${this.latestOastTokenData.token} ready for injection!`
          });
        }
      } catch (err) {
        alert('Failed to generate OAST token: ' + err);
      } finally {
        this.isGeneratingOast = false;
      }
    },

    async clearAllOastEvents() {
      if (!confirm('Clear all recorded out-of-band callback events?')) return;
      const proj = this.selectedProject;
      try {
        const resp = await fetch(`/api/oast/events?project=${encodeURIComponent(proj)}`, {
          method: 'DELETE'
        });
        if (resp.ok) {
          this.oastEvents = [];
          this.showToast({
            title: 'OAST Cleared',
            message: 'Out-of-band events ledger wiped clean.'
          });
        }
      } catch (err) {
        console.error('Failed to clear OAST events:', err);
      }
    },

    filteredOastEvents() {
      if (!this.oastEvents) return [];
      const q = (this.oastSearchQuery || '').toLowerCase().trim();
      if (!q) return this.oastEvents;

      return this.oastEvents.filter(ev => {
        return (ev.token && ev.token.toLowerCase().includes(q)) ||
          (ev.client_ip && ev.client_ip.includes(q)) ||
          (ev.method && ev.method.toLowerCase().includes(q)) ||
          (ev.path && ev.path.toLowerCase().includes(q)) ||
          (ev.request_body && ev.request_body.toLowerCase().includes(q));
      });
    }
  }
};
