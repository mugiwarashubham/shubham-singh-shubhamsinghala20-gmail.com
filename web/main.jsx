import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const api = async (path, { token, method = 'GET', body } = {}) => {
  const response = await fetch(`/v1${path}`, {
    method,
    credentials: 'include',
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      'content-type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(data?.error?.message || 'Request failed');
    error.payload = data?.error;
    error.status = response.status;
    throw error;
  }

  return data;
};

const has = (permissions, key) =>
  permissions?.[key]?.effect === 'allow';

function ErrorBox({ error, testId }) {
  if (!error) return null;

  return (
    <div className="error" role="alert" data-testid={testId}>
      {error.message || String(error)}
    </div>
  );
}

function Login({ onLogin }) {
  const [email, setEmail] = useState('dana@example.test');
  const [password, setPassword] = useState('demo1234');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();

    if (!email || !password) {
      setError(new Error('Email and password are required'));
      return;
    }

    setBusy(true);
    setError(null);

    try {
      const data = await api('/auth/login', {
        method: 'POST',
        body: { email, password },
      });

      onLogin(data);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="login">
      <div className="login-card">
        <div className="brand">RemoteOps</div>
        <h1>Sign in</h1>
        <p className="muted">
          Permission-aware remote operations console
        </p>

        <ErrorBox error={error} testId="login-error" />

        <form data-testid="login-form" onSubmit={submit}>
          <label>
            Email
            <input
              data-testid="login-email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </label>

          <label>
            Password
            <input
              data-testid="login-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>

          <button
            data-testid="login-submit"
            className="primary"
            disabled={busy}
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <small>Demo: dana@example.test / demo1234</small>
      </div>
    </main>
  );
}

function App() {
  const [token, setToken] = useState(null);
  const [me, setMe] = useState(null);
  const [error, setError] = useState(null);
  const [page, setPage] = useState('devices');

  const load = async (nextToken) => {
    try {
      const data = await api('/auth/me', { token: nextToken });

      setToken(nextToken);
      setMe(data);
      setError(null);
    } catch (err) {
      setToken(null);
      setMe(null);

      if (err.status !== 401) {
        setError(err);
      }
    }
  };

  useEffect(() => {
    api('/auth/refresh', { method: 'POST' })
      .then((data) => load(data.token))
      .catch(() => {});
  }, []);

  if (!me) {
    return token ? (
      <div className="loading">Loading…</div>
    ) : (
      <Login onLogin={(data) => load(data.token)} />
    );
  }

  return (
    <Console
      token={token}
      me={me}
      setMe={setMe}
      setToken={setToken}
      page={page}
      setPage={setPage}
      error={error}
      setError={setError}
      logout={() => {
        setToken(null);
        setMe(null);
      }}
    />
  );
}

function Console({
  token,
  me,
  setMe,
  setToken,
  page,
  setPage,
  error,
  setError,
  logout,
}) {
  const org = me.org;
  const permissions = me.permissions;

  const themeColors = {
    cobalt: '#eef3ff',
    amber: '#fff7e6',
    moss: '#edf7ed',
    plum: '#f5effa',
    rust: '#fff0eb',
    teal: '#e9f8f7',
  };

  const nav = [
    ['devices', 'Devices', 'device:list'],
    ['people', 'People', 'user:read'],
    ['grants', 'Grants', 'user:read'],
    ['sessions', 'Sessions', 'session:view'],
    ['audit', 'Audit', 'audit:read'],
    ['admin', 'Admin', 'org:update'],
  ].filter((item) => has(permissions, item[2]));

  const switchOrg = async (id) => {
    try {
      const data = await api('/auth/token', {
        token,
        method: 'POST',
        body: { orgId: id },
      });

      const nextToken = data.token;
      const nextMe = await api('/auth/me', { token: nextToken });

      // Keep the new org token in memory. Do not persist it in web storage.
      setToken(nextToken);
      setMe(nextMe);
      setPage('devices');
      setError(null);
    } catch (err) {
      setError(err);
    }
  };

  const createOrg = async () => {
    const name = window.prompt('Organization name');

    if (!name) return;

    try {
      const data = await api('/orgs', {
        token,
        method: 'POST',
        body: { name },
      });

      await switchOrg(data.id);
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div
      className="shell"
      style={{
        backgroundColor: themeColors[org.theme] || '#f5f7fa',
      }}
      data-testid="app-shell"
      data-org-id={org.id}
      data-org-theme={org.theme}
    >
      <aside>
        <div className="logo">RemoteOps</div>

        <div className="orgs">
          {me.orgs.map((item) => (
            <button
              key={item.id}
              data-testid="org-option"
              data-org-id={item.id}
              className={item.id === org.id ? 'org active' : 'org'}
              onClick={() => switchOrg(item.id)}
            >
              <span className="dot" data-theme={item.theme} />
              <span>{item.name}</span>
              <small>{item.role}</small>
            </button>
          ))}

          <button
            className="create"
            data-testid="create-org"
            onClick={createOrg}
          >
            ＋ New organization
          </button>
        </div>

        <nav>
          {nav.map(([id, label, permission]) => (
            <button
              key={id}
              data-testid={`nav-${id}`}
              data-permission={permission}
              data-state="unlocked"
              onClick={() => setPage(id)}
              className={page === id ? 'selected' : ''}
            >
              {label}
            </button>
          ))}
        </nav>

        <button className="logout" onClick={logout}>
          Sign out
        </button>
      </aside>

      <main className="content">
        <header>
          <div>
            <span className="eyebrow">Organization</span>
            <h2>{org.name}</h2>
          </div>

          <div className="role" data-testid="active-role">
            {me.role}
          </div>
        </header>

        <ErrorBox error={error} />

        {page === 'devices' && (
          <Devices token={token} me={me} setError={setError} />
        )}

        {page === 'people' && (
          <People token={token} me={me} setError={setError} />
        )}

        {page === 'grants' && (
          <Grants token={token} me={me} setError={setError} />
        )}

        {page === 'sessions' && (
          <Sessions token={token} setError={setError} />
        )}

        {page === 'audit' && (
          <Audit token={token} setError={setError} />
        )}

        {page === 'admin' && (
          <Admin token={token} me={me} setError={setError} />
        )}
      </main>
    </div>
  );
}

function Devices({ token, me, setError }) {
  const [devices, setDevices] = useState(null);

  useEffect(() => {
    api(`/orgs/${me.org.id}/devices`, { token })
      .then((data) => setDevices(data.devices))
      .catch(setError);
  }, [token, me.org.id]);

  if (!devices) {
    return <div className="panel">Loading devices…</div>;
  }

  return (
    <section>
      <div className="section-head">
        <div>
          <span className="eyebrow">Fleet</span>
          <h3>Devices</h3>
        </div>
        <span className="count">{devices.length}</span>
      </div>

      {devices.length === 0 ? (
        <div className="empty" data-testid="devices-empty">
          No devices in this organization yet.
        </div>
      ) : (
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Platform</th>
                <th>Status</th>
                <th>Access</th>
                <th />
              </tr>
            </thead>

            <tbody>
              {devices.map((device) => (
                <tr
                  key={device.id}
                  data-testid="device-row"
                  data-device-id={device.id}
                >
                  <td>
                    <strong>{device.name}</strong>
                    <small>{device.id}</small>
                  </td>

                  <td>{device.kind}</td>

                  <td>
                    <span
                      className={device.online ? 'online' : 'offline'}
                    >
                      {device.online ? 'Online' : 'Offline'}
                    </span>
                  </td>

                  <td>
                    <div className="chips">
                      {['device:view', 'device:control', 'device:terminal'].map(
                        (permission) =>
                          has(device.permissions, permission) && (
                            <span
                              key={permission}
                              className="chip"
                              {...(permission !== 'device:control'
                                ? { 'data-permission': permission }
                                : {})}
                            >
                              {permission.split(':')[1]}
                            </span>
                          )
                      )}
                    </div>
                  </td>

                  <td>
                    {has(device.permissions, 'device:control') && (
                      <button
                        data-permission="device:control"
                        data-state="unlocked"
                        className="small"
                      >
                        Control
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function People({ token, me, setError }) {
  const [members, setMembers] = useState(null);

  useEffect(() => {
    api(`/orgs/${me.org.id}/members`, { token })
      .then((data) => setMembers(data.members))
      .catch(setError);
  }, [token, me.org.id]);

  return (
    <section>
      <div className="section-head">
        <div>
          <span className="eyebrow">Directory</span>
          <h3>People</h3>
        </div>
      </div>

      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>Person</th>
              <th>Role</th>
              <th>Status</th>
            </tr>
          </thead>

          <tbody>
            {members?.map((member) => (
              <tr
                key={member.user_id}
                data-testid="user-row"
                data-user-id={member.user_id}
              >
                <td>
                  <strong>{member.name}</strong>
                  <small>{member.email}</small>
                </td>
                <td>{member.role}</td>
                <td>{member.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Grants({ token, me, setError }) {
  const [grants, setGrants] = useState([]);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [open, setOpen] = useState(false);

  const reload = () =>
    Promise.all([
      api(`/orgs/${me.org.id}/grants`, { token }),
      api(`/orgs/${me.org.id}/members`, { token }),
      api(`/orgs/${me.org.id}/devices`, { token }),
    ])
      .then(([grantData, memberData, deviceData]) => {
        setGrants(grantData.grants);
        setMembers(memberData.members);
        setDevices(deviceData.devices);
      })
      .catch(setError);

  useEffect(() => {
    reload();
  }, [token, me.org.id]);

  const canCreate = has(me.permissions, 'grant:create');

  const submit = async (event) => {
    event.preventDefault();

    const form = new FormData(event.currentTarget);
    const permissions = form.getAll('permission');

    try {
      await api(`/orgs/${me.org.id}/grants`, {
        token,
        method: 'POST',
        body: {
          userId: form.get('user'),
          deviceId: form.get('device') || null,
          effect: form.get('effect'),
          permissions,
        },
      });

      setOpen(false);
      await reload();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <section>
      <div className="section-head">
        <div>
          <span className="eyebrow">Authorization</span>
          <h3>Grants</h3>
        </div>

        {canCreate && (
          <button
            data-testid="new-grant"
            className="primary small"
            onClick={() => setOpen(true)}
          >
            New grant
          </button>
        )}
      </div>

      {open && (
        <form className="panel form-grid" onSubmit={submit}>
          <label>
            User
            <select name="user" data-testid="grant-user">
              {members.map((member) => (
                <option value={member.user_id} key={member.user_id}>
                  {member.name}
                </option>
              ))}
            </select>
          </label>

          <label>
            Device
            <select name="device" data-testid="grant-device">
              <option value="">All devices</option>
              {devices.map((device) => (
                <option value={device.id} key={device.id}>
                  {device.name}
                </option>
              ))}
            </select>
          </label>

          <label>
            Effect
            <select name="effect" data-testid="grant-effect">
              <option value="allow">allow</option>
              <option value="deny">deny</option>
            </select>
          </label>

          <fieldset>
            <legend>Permission</legend>

            <label>
              <input
                type="checkbox"
                name="permission"
                value="device:terminal"
                data-permission-key="device:terminal"
              />
              device:terminal
            </label>

            <label>
              <input
                type="checkbox"
                name="permission"
                value="device:control"
                data-permission-key="device:control"
              />
              device:control
            </label>

            <label>
              <input
                type="checkbox"
                name="permission"
                value="session:start"
                data-permission-key="session:start"
              />
              session:start
            </label>
          </fieldset>

          <div>
            <button data-testid="grant-submit" className="primary">
              Create
            </button>
          </div>
        </form>
      )}

      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Scope</th>
              <th>Effect</th>
              <th>Permissions</th>
              <th />
            </tr>
          </thead>

          <tbody>
            {grants.map((grant) => (
              <tr
                data-testid="grant-row"
                data-effect={grant.effect}
                key={grant.id}
              >
                <td>
                  {members.find(
                    (member) => member.user_id === grant.user_id
                  )?.name || grant.user_id}
                </td>

                <td>{grant.device_id || 'Organization'}</td>
                <td>{grant.effect}</td>
                <td>{grant.permissions.join(', ')}</td>

                <td>
                  {has(me.permissions, 'grant:revoke') && (
                    <button
                      data-testid="revoke-grant"
                      className="link"
                      onClick={async () => {
                        try {
                          await api(
                            `/orgs/${me.org.id}/grants/${grant.id}`,
                            { token, method: 'DELETE' }
                          );
                          await reload();
                        } catch (err) {
                          setError(err);
                        }
                      }}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Sessions({ token, setError }) {
  const [rows, setRows] = useState(null);

  useEffect(() => {
    api('/auth/me', { token })
      .then((me) =>
        api(`/orgs/${me.org.id}/sessions`, { token })
      )
      .then((data) => setRows(data.sessions))
      .catch(setError);
  }, [token]);

  return (
    <section>
      <div className="section-head">
        <div>
          <span className="eyebrow">Activity</span>
          <h3>Sessions</h3>
        </div>
      </div>

      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>User</th>
              <th>Mode</th>
              <th>State</th>
              <th>Expires</th>
            </tr>
          </thead>

          <tbody>
            {rows?.map((row) => (
              <tr key={row.id}>
                <td>{row.device_name}</td>
                <td>{row.user_name}</td>
                <td>{row.mode}</td>
                <td>{row.state}</td>
                <td>{new Date(row.expires_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Audit({ token, setError }) {
  const [rows, setRows] = useState(null);

  useEffect(() => {
    api('/auth/me', { token })
      .then((me) =>
        api(`/orgs/${me.org.id}/audit`, { token })
      )
      .then((data) => setRows(data.events))
      .catch(setError);
  }, [token]);

  return (
    <section>
      <div className="section-head">
        <div>
          <span className="eyebrow">Trace</span>
          <h3>Audit log</h3>
        </div>
      </div>

      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Result</th>
              <th>Reason</th>
            </tr>
          </thead>

          <tbody>
            {rows?.map((row) => (
              <tr key={row.id}>
                <td>{new Date(row.at).toLocaleString()}</td>
                <td>{row.action}</td>
                <td>{row.result}</td>
                <td>{row.reason_code || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Admin({ token, me, setError }) {
  const rename = async () => {
    const name = prompt(
      'New organization name',
      me.org.name
    );

    if (!name) return;

    try {
      await api(`/orgs/${me.org.id}`, {
        token,
        method: 'PATCH',
        body: { name },
      });

      window.location.reload();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <section>
      <div className="section-head">
        <div>
          <span className="eyebrow">Administration</span>
          <h3>Organization settings</h3>
        </div>
      </div>

      <div className="panel admin">
        <p>Manage the active organization.</p>

        {has(me.permissions, 'org:update') && (
          <button
            data-testid="rename-org"
            className="primary"
            onClick={rename}
          >
            Rename organization
          </button>
        )}

        {has(me.permissions, 'org:delete') && (
          <button
            data-testid="delete-org"
            className="danger"
          >
            Delete organization
          </button>
        )}
      </div>
    </section>
  );
}

function InvitePage({ token }) {
  const [info, setInfo] = useState(null);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(false);
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');

  useEffect(() => {
    api(`/invites/${token}`)
      .then(setInfo)
      .catch(setError);
  }, [token]);

  if (done) {
    return <Login onLogin={() => {}} />;
  }

  if (!info) {
    return (
      <main className="login">
        <div className="login-card">
          <ErrorBox error={error} testId="invite-error" />
          <p>Loading invite…</p>
        </div>
      </main>
    );
  }

  const accept = async () => {
    try {
      await api(`/invites/${token}/accept`, {
        method: 'POST',
        body: {
          email: info.email,
          name,
          password,
        },
      });

      setDone(true);
    } catch (err) {
      setError(err);
    }
  };

  return (
    <main className="login">
      <div className="login-card">
        <div className="brand">RemoteOps</div>

        <h1>Join {info.orgName}</h1>

        <p className="muted">
          Role: <strong data-testid="invite-role">{info.role}</strong>
        </p>

        <input
          data-testid="invite-email"
          value={info.email}
          readOnly
        />

        <input
          data-testid="invite-name"
          placeholder="Your name"
          value={name}
          onChange={(event) => setName(event.target.value)}
        />

        <input
          data-testid="invite-password"
          type="password"
          placeholder="Password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />

        <button
          data-testid="invite-submit"
          className="primary"
          onClick={accept}
        >
          Accept invite
        </button>

        <ErrorBox error={error} testId="invite-error" />
      </div>
    </main>
  );
}

function Root() {
  const invite = location.pathname.match(/^\/invite\/(.+)$/);

  return invite ? (
    <InvitePage token={decodeURIComponent(invite[1])} />
  ) : (
    <App />
  );
}

createRoot(document.getElementById('root')).render(<Root />);
