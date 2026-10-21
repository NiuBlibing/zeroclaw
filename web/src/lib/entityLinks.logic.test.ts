import assert from 'node:assert/strict';
import test from 'node:test';
import { entityConfigPath } from './entityLinks.ts';

test('provider links use the longest configured profile boundary', () => {
  const aliases = ['gw', 'gw.v2'];
  assert.equal(entityConfigPath('model-provider', 'custom.gw.fast', aliases), '/config/providers.models/custom/gw');
  assert.equal(entityConfigPath('model-provider', 'custom.gw.v2', aliases), '/config/providers.models/custom/gw.v2');
  assert.equal(entityConfigPath('model-provider', 'custom.gw.v2.fast', aliases), '/config/providers.models/custom/gw.v2');
  assert.equal(entityConfigPath('model-provider', 'openrouter.glm-5.2', ['glm-5.2']), '/config/providers.models/openrouter/glm-5.2');
});

test('unresolved provider links go to the provider list', () => {
  assert.equal(entityConfigPath('model-provider', 'custom.gw.fast'), '/config/providers.models');
  assert.equal(entityConfigPath('channel', 'telegram.work.v2'), '/config/channels/telegram/work.v2');
});
