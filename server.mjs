import * as path from 'node:path';
import { strict as assert } from 'node:assert';
import { inspect } from 'node:util';
import * as querystring from 'node:querystring';
import express from 'express';
import Provider from 'oidc-provider';
import { interactionPolicy } from 'oidc-provider';
import pino from 'pino-http';
import { urlencoded } from 'express';
import { dirname } from 'desm';

import Account from './support/account.mjs';

const body = urlencoded({ extended: false });
const __dirname = dirname(import.meta.url);

const app = express();

const logger = pino({
  transport: { target: 'pino-pretty', options: { colorize: true } },
});
app.use(logger);


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

const interactions = interactionPolicy.base();
interactions.add(new interactionPolicy.Prompt({
  name: 'select_account',
  requestable: true,
}), 0);


// Map of file extensions to mime types
const configuration = {
  clients: [{
    client_id: 'aaa-client',
    client_secret: 'aaa-secret',
    redirect_uris: [
      'https://connectify-staging-xckvrr.zitadel.cloud/ui/login/login/externalidp/callback',
    ],
  }],
  pkce: {
    required: () => false,
  },
  interactions: {
    policy: interactions,
  },
  // async loadExistingGrant(ctx) {
  //   const grant = new ctx.oidc.provider.Grant({
  //     clientId: ctx.oidc.client.clientId,
  //     accountId: ctx.oidc.session.accountId,
  //   });
  //
  //   grant.addOIDCScope('openid email profile');
  //   grant.addOIDCClaims(['first_name']);
  //   grant.addResourceScope('urn:example:resource-indicator', 'api:read api:write');
  //   await grant.save();
  //   return grant;
  // }
}

const issuer = 'https://oidc.congee.me';
const provider = new Provider(issuer, configuration);

provider.on('interaction.started', () => console.log('interaction.started'));

function setNoCache(req, res, next) {
  res.set('cache-control', 'no-store');
  next();
}

const keys = new Set();
const debug = (obj) => querystring.stringify(Object.entries(obj).reduce((acc, [key, value]) => {
  keys.add(key);
  if (!value) return acc;
  acc[key] = inspect(value, { depth: null });
  return acc;
}, {}), '<br/>', ': ', {
  encodeURIComponent(value) { return keys.has(value) ? `<strong>${value}</strong>` : value; },
});

app.use((req, res, next) => {
  const orig = res.render;
  // you'll probably want to use a full blown render engine capable of layouts
  res.render = (view, locals) => {
    app.render(view, locals, (err, html) => {
      if (err) throw err;
      orig.call(res, '_layout', {
        ...locals,
        body: html,
      });
    });
  };
  next();
});

app.get('/interaction/:uid', setNoCache, async (req, res, next) => {
  const details = await provider.interactionDetails(req, res);
  if (details.params.prompt === 'select_account') {
    details.params.prompt = 'login';
    details.prompt.name = 'login';
    details.prompt.reasons = [];
  }
  const { uid, prompt, params, session } = details;

  const client = await provider.Client.find(params.client_id);
  console.log('++++++++++++++++++++++++++++++++ interaction details ++++++++++++++++++++++')
  console.warn(JSON.stringify(details));

  try {
    switch (prompt.name) {
      case 'login': {
        return res.render('login', {
          client,
          uid,
          details: prompt.details,
          params,
          title: 'Sign-in',
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt),
          },
        });
      }
      case 'consent': {
        return res.render('interaction', {
          client,
          uid,
          details: prompt.details,
          params,
          title: 'Authorize',
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt),
          },
        });
      }
      default:
        return undefined;
    }
  } catch (err) {
    return next(err);
  }
});

app.post('/interaction/:uid/login', setNoCache, body, async (req, res, next) => {
  try {
    const details = await provider.interactionDetails(req, res);
    console.log('++++++++++++++++++++++++++++++++ login details ++++++++++++++++++++++')
    console.warn(details);

    const { prompt: { name } } = details;
    assert.equal(name, 'login');
    const account = await Account.findByLogin(req.body.login);

    const result = {
      login: {
        accountId: account.accountId,
      },
    };

    return await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
  } catch (err) {
    next(err);
  }
});

app.post('/interaction/:uid/confirm', setNoCache, body, async (req, res, next) => {
  try {
    const interactionDetails = await provider.interactionDetails(req, res);
    console.log('++++++++++++++++++++++++++++++++ confirm details ++++++++++++++++++++++')
    console.warn(interactionDetails);
    const { prompt: { name, details }, params, session: { accountId } } = interactionDetails;
    assert.equal(name, 'consent');

    let { grantId } = interactionDetails;
    let grant;

    if (grantId) {
      // we'll be modifying existing grant in existing session
      grant = await provider.Grant.find(grantId);
    } else {
      // we're establishing a new grant
      grant = new provider.Grant({
        accountId,
        clientId: params.client_id,
      });
    }

    if (details.missingOIDCScope) {
      grant.addOIDCScope(details.missingOIDCScope.join(' '));
    }
    if (details.missingOIDCClaims) {
      grant.addOIDCClaims(details.missingOIDCClaims);
    }
    if (details.missingResourceScopes) {
      for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
        grant.addResourceScope(indicator, scopes.join(' '));
      }
    }

    grantId = await grant.save();

    const consent = {};
    if (!interactionDetails.grantId) {
      // we don't have to pass grantId to consent, we're just modifying existing one
      consent.grantId = grantId;
    }

    const result = { consent };

    console.log('++++++++++++++++++++++++++++++++ confirm result ++++++++++++++++++++++')
    console.warn(result);

    await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
  } catch (err) {
    next(err);
  }
});

app.get('/interaction/:uid/abort', setNoCache, async (req, res, next) => {
  try {
    const result = {
      error: 'access_denied',
      error_description: 'End-User aborted interaction',
    };
    await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
  } catch (err) {
    next(err);
  }
});

app.use(provider.callback());

// set up web server
const server = app.listen(3000, () => {
  console.log('Server is listening on port 3000')
});
