// Fixture for recon tests. Not real code.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication().AddJwtBearer();
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader()));
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
var books = app.MapGroup("/api/books");
books.MapGet("/{id}", (int id, LibraryDb db) => db.Books.Find(id)).RequireAuthorization();
books.MapPost("/", (Book book, LibraryDb db) => db.Add(book));
app.MapGet("/health", () => "ok").AllowAnonymous();
var conn = builder.Configuration.GetConnectionString("Library");
app.MapControllers();
app.Run();
