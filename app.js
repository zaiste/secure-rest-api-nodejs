const Huncwot = require('huncwot');
const {
  ok,
  json,
  notFound,
  created,
  unauthorized
} = require('huncwot/response');
const { can, register, login } = require('huncwot/auth');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const db = require('huncwot/db');

const app = new Huncwot();

const hash = bcrypt.hash;
const compare = bcrypt.compare;

const makeSession = async person_id => {
  const token = await new Promise((resolve, reject) => {
    crypto.randomBytes(16, (error, data) => {
      error ? reject(error) : resolve(fromBase64(data.toString('base64')));
    });
  });

  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('base64');

  await db`session`.insert({ token: hashedToken, person_id });

  return token;
};

app.get('/', _ => 'Hello, Huncwot');
app.get('/a', can, _ => 'Hello, Secure');
app.get('/name/:name', ({ params }) => `Hello, your name is ${params.name}`);
app.get('/json', _ => json({ widget: 'This is widget 1' }));
app.get('/secure', async ({ headers, params }) => {
  const { authorization: token } = headers;

  if (!token) return unauthorized();

  const hash = crypto
    .createHash('sha256')
    .update(token)
    .digest('base64');

  const [found] = await db`session`({ token: hash });

  if (!found) return unauthorized();

  return json({ secret: 'This message is only for admins!' });
});

app.post('/register', async ({ params }) => {
  const { password } = params;
  const hashed_password = await hash(password, 10);

  let person = {
    name: params.name,
    email: params.email,
    password: hashed_password
  };

  const [{ id: person_id }] = await db
    .from('person')
    .insert(person)
    .return('id');

  const token = await makeSession(person_id);

  return json({ token, person_id });
});

app.post('/login', async ({ params }) => {
  const { password } = params;

  const [person] = await db.from('person').where({ email: params.email });

  if (!person) return unauthorized();

  const match = await compare(password, person.password);

  if (!match) return unauthorized();

  // create session
  const token = await makeSession(person.id);

  delete person.password;

  return created({ token, ...person }, { Authorization: token });
});

const widgets = [
  {
    id: 1,
    name: 'Widget 1'
  }
];

let _id = 1;

const browse = _ => json(widgets);

const read = ({ params: { id } }) => json(widgets.find(_ => _.id === +id));

const add = ({ params: { name } }) => {
  const id = ++_id;

  widgets.push({ id, name });

  return created({ id, name });
};

const edit = ({ params: { id, name } }) => {
  const widget = widgets.find(_ => _.id === +id);

  if (!widget) return notFound();

  widget.name = name;
  return json({ id, name });
};

const destroy = ({ params: { id } }) => {
  const widgetIndex = widgets.findIndex(_ => _.id === +id);

  if (widgetIndex < 0) return notFound();

  widgets.splice(widgetIndex, 1);
  return ok();
};

const finder = async ({ email }) => {
  const result = await db.from('person').where({ email });
  return result;
};

app.post('/register2', register({ fields: ['name', 'email'] }));
app.post('/login2', login({ finder }));

app.get('/widgets', browse);
app.get('/widgets/:id', read);
app.post('/widgets', can(add));
app.patch('/widgets/:id', can(edit));
app.delete('/widgets/:id', destroy);

app.listen(5544);
