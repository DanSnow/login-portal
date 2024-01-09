<script setup lang="ts">
import { ref } from 'vue'
import { Button } from '~/components/ui/button'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '~/components/ui/card'
import { Input } from '~/components/ui/input'
import { Label } from '~/components/ui/label'
import { client } from '~/api'

const { mutateAsync } = client.login.useMutation()
const showError = ref(false)
const state = ref({
  email: '',
  password: '',
})

async function handleLogin() {
  showError.value = false
  const res = await mutateAsync({
    body: state.value,
  })
  if (res.status !== 200) {
    showError.value = true
  }
}
</script>

<template>
  <Card>
    <CardHeader class="space-y-1">
      <CardTitle class="text-2xl"> Login </CardTitle>
    </CardHeader>
    <CardContent class="grid gap-4">
      <div class="grid gap-2">
        <Label for="email">Email</Label>
        <Input v-model="state.email" id="email" type="email" placeholder="m@example.com" />
      </div>
      <div class="grid gap-2">
        <Label for="password">Password</Label>
        <Input v-model="state.password" id="password" type="password" />
        <div v-if="showError" class="text-red-400">Login fail</div>
      </div>
    </CardContent>
    <CardFooter>
      <Button class="w-full" @click="handleLogin"> Login </Button>
    </CardFooter>
  </Card>
</template>
