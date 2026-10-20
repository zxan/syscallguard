import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Bridge URL baked in at build time: SG_BRIDGE_URL if set, else the VM's reserved libvirt IP.
// At run time ?bridge=ws://host:port overrides it (see src/App.tsx).
export default defineConfig({
  base: "./", // relative asset paths: the build works from any directory or static server
  plugins: [react()],
  define: {
    __SG_BRIDGE_URL__: JSON.stringify(process.env.SG_BRIDGE_URL || "ws://192.168.122.174:8765"),
  },
});
