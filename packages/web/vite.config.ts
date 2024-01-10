import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'node:path'
import url from 'node:url'

const __dirname = url.fileURLToPath(new URL('.', import.meta.url))

// https://vitejs.dev/config/
export default defineConfig({
	resolve: {
		alias: {
			'~': path.join(__dirname, 'src'),
		},
	},
	build: {
		assetsDir: '_auth/assets',
	},
	plugins: [vue()],
})
