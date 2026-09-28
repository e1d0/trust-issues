// Fixture for recon tests. Not real code.
const app = express();
app.get('/profile', requireAuth, async (req, res) => {
  const partner = await axios.get('/partners/' + req.query.id);
  res.json(partner.data);
});
app.post('/share', async (req, res) => {
  console.log('share', req.headers);
  res.redirect(req.query.next);
});
