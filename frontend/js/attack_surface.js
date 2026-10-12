/**
 * Spectra / AetherGate - Attack Surface Knowledge Graph Component
 */

window.AttackSurfaceModule = {
  data() {
    return {
      attackSurfaceData: { summary: {}, assets: [] },
      attackSurfaceSearch: '',
      attackSurfaceStatusFilter: 'ALL',
      selectedAssetId: null,
      showAddAssetModal: false,
      newAssetForm: {
        host: '',
        ip: '',
        os_info: '',
        tags: '',
        notes: ''
      },
      showAddServiceModal: false,
      newServiceForm: {
        host: '',
        port: 80,
        protocol: 'tcp',
        service_name: 'http',
        banner: '',
        state: 'open'
      }
    };
  },

  methods: {
    async fetchAttackSurface() {
      const proj = this.selectedProject || 'default';
      try {
        const resp = await fetch(`/api/targets/graph?project=${encodeURIComponent(proj)}`);
        if (resp.ok) {
          this.attackSurfaceData = await resp.json();
          this.$nextTick(() => {
            if (window.lucide) lucide.createIcons();
          });
        }
      } catch (err) {
        console.error('Failed to fetch attack surface graph:', err);
      }
    },

    filteredAssets() {
      if (!this.attackSurfaceData || !this.attackSurfaceData.assets) return [];
      const q = (this.attackSurfaceSearch || '').toLowerCase().trim();
      const statusF = this.attackSurfaceStatusFilter || 'ALL';

      return this.attackSurfaceData.assets.filter(a => {
        const hostMatch = !q || (a.host && a.host.toLowerCase().includes(q)) || (a.ip && a.ip.includes(q)) || (a.os_info && a.os_info.toLowerCase().includes(q));
        if (!hostMatch) return false;

        if (statusF !== 'ALL') {
          const hasMatchingStatus = (a.endpoints || []).some(ep => ep.tested_status === statusF);
          if (!hasMatchingStatus) return false;
        }
        return true;
      });
    },

    async saveNewAsset() {
      if (!this.newAssetForm.host) {
        alert('Hostname/Domain is required.');
        return;
      }
      try {
        const payload = {
          project: this.selectedProject === 'ALL' ? 'default' : this.selectedProject,
          host: this.newAssetForm.host,
          ip: this.newAssetForm.ip,
          os_info: this.newAssetForm.os_info,
          tags: this.newAssetForm.tags ? this.newAssetForm.tags.split(',').map(t => t.trim()) : [],
          notes: this.newAssetForm.notes
        };
        const resp = await fetch('/api/targets/assets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (resp.ok) {
          this.showAddAssetModal = false;
          this.newAssetForm = { host: '', ip: '', os_info: '', tags: '', notes: '' };
          await this.fetchAttackSurface();
        }
      } catch (err) {
        alert('Failed to save asset: ' + err);
      }
    },

    async saveNewService() {
      if (!this.newServiceForm.host || !this.newServiceForm.port) {
        alert('Host and Port are required.');
        return;
      }
      try {
        const payload = {
          project: this.selectedProject === 'ALL' ? 'default' : this.selectedProject,
          host: this.newServiceForm.host,
          port: parseInt(this.newServiceForm.port),
          protocol: this.newServiceForm.protocol || 'tcp',
          service_name: this.newServiceForm.service_name || 'unknown',
          banner: this.newServiceForm.banner || '',
          state: this.newServiceForm.state || 'open'
        };
        const resp = await fetch('/api/targets/services', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (resp.ok) {
          this.showAddServiceModal = false;
          await this.fetchAttackSurface();
        }
      } catch (err) {
        alert('Failed to save service: ' + err);
      }
    },

    async updateEndpointStatus(endpointId, newStatus) {
      try {
        const resp = await fetch(`/api/targets/endpoints/${endpointId}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tested_status: newStatus })
        });
        if (resp.ok) {
          await this.fetchAttackSurface();
        }
      } catch (err) {
        console.error('Failed to update endpoint status:', err);
      }
    },

    async deleteAsset(assetId) {
      if (!confirm(`Are you sure you want to delete asset #${assetId} and all associated services/endpoints?`)) return;
      try {
        const resp = await fetch(`/api/targets/assets/${assetId}`, { method: 'DELETE' });
        if (resp.ok) {
          await this.fetchAttackSurface();
        }
      } catch (err) {
        console.error('Failed to delete asset:', err);
      }
    },

    sendEndpointToRepeater(ep) {
      if (!ep || !ep.url) return;
      this.currentAppTab = 'repeater';
      const activeTab = this.activeRepeaterTab;
      if (activeTab) {
        activeTab.url = ep.url;
        activeTab.method = ep.method || 'GET';
      }
      this.$nextTick(() => {
        if (window.lucide) lucide.createIcons();
      });
    }
  }
};
