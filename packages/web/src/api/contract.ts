import { initContract } from '@ts-rest/core'
import { z } from 'zod'

const c = initContract()

export const apiRouter = c.router(
  {
    login: {
      method: 'POST',
      path: '/login',
      body: z.object({
        email: z.string().email(),
        password: z.string(),
      }),
      responses: {
        200: z.object({
          ok: z.literal(true),
        }),
        401: z.object({
          ok: z.literal(false),
        }),
      },
    },
  },
  {
    pathPrefix: '/_auth/api/v1',
    validateResponseOnClient: true,
  },
)
