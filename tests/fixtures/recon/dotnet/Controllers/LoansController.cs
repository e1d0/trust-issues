// Fixture for recon tests. Not real code.
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class LoansController : ControllerBase
{
    [HttpGet("{loanId}")]
    public IActionResult Get(string loanId) => Ok(_db.Loans.FromSqlRaw($"SELECT * FROM Loans WHERE Id = '{loanId}'"));

    [AllowAnonymous]
    [HttpPost("reminders")]
    public IActionResult Remind() => Ok();
}
