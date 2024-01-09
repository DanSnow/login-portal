import { initQueryClient } from '@ts-rest/vue-query'
import { apiRouter } from './contract'

export const client = initQueryClient(apiRouter, {
  baseUrl: location.origin,
  baseHeaders: {},
})
