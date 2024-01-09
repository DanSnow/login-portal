<script setup lang="ts">
import { Button } from '~/components/ui/button'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '~/components/ui/card'
import { Input } from '~/components/ui/input'
import { Label } from '~/components/ui/label'
</script>

<template>
  <Card>
    <CardHeader class="space-y-1">
      <CardTitle class="text-2xl"> Login </CardTitle>
    </CardHeader>
    <CardContent class="grid gap-4">
      <div class="grid gap-2">
        <Label for="email">Email</Label>
        <Input id="email" type="email" placeholder="m@example.com" />
      </div>
      <div class="grid gap-2">
        <Label for="password">Password</Label>
        <Input id="password" type="password" />
      </div>
    </CardContent>
    <CardFooter>
      <Button class="w-full"> Login </Button>
    </CardFooter>
  </Card>
</template>
