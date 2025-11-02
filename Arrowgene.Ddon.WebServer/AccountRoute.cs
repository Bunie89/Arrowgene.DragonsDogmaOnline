using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Arrowgene.Ddon.Database;
using Arrowgene.Ddon.Database.Model;
using Arrowgene.Ddon.Shared.Crypto;
using Arrowgene.Ddon.Shared.Model;
using Arrowgene.Logging;
using Arrowgene.WebServer;
using Arrowgene.WebServer.Route;

namespace Arrowgene.Ddon.WebServer
{
    public class AccountRoute : WebRoute
    {
        private static readonly ILogger Logger = LogProvider.Logger<Logger>(typeof(AccountRoute));


        public override string Route => "/api/account";

        private readonly IDatabase _database;

        private class AccountRequest
        {
            public string Action { get; set; }
            public string Account { get; set; }
            public string Password { get; set; }
        }

        private class AccountResponse
        {
            public string Error { get; set; }
            public string Message { get; set; }
            public string Token { get; set; }
        }

        private class AccountRouteException(string message) : Exception(message)
        {
        }

        private class AccountVerification
        {
            public bool Error { get; set; }
            public string Message { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }

            public AccountVerification(string username, string password)
            {
                Username = username;
                Password = password;

                // Very simple data checks on the parameters.

                if (Username.Trim().Length == 0)
                {
                    throw new AccountRouteException("Account ID cannot be empty.");
                }

                // Disallow any whitespace.

                if (Regex.IsMatch(Username, @"\s"))
                {
                    throw new AccountRouteException("Account ID cannot contain spaces.");
                }

                if (Password.Trim().Length == 0)
                {
                    throw new AccountRouteException("Password cannot be empty.");
                }

                if (Regex.IsMatch(Password, @"\s"))
                {
                    throw new AccountRouteException("Password cannot contain spaces.");
                }
            }
        }

        public AccountRoute(IDatabase database)
        {
            _database = database;
        }

        public override async Task<WebResponse> Post(WebRequest request)
        {
            AccountRequest req = await request.ReadJsonAsync<AccountRequest>();
            if (req == null)
            {
                return await WebResponse.InternalServerError();
            }

            AccountResponse res = new();
            WebResponse response = new();

            try
            {
                AccountVerification accountCheck = new(req.Account, req.Password);

                if (_database.CheckBannedIp(request.Host))
                {
                    throw new AccountRouteException("Your IP has been banned.");
                }

                switch (req.Action)
                {
                    case "login":
                        string token = CreateToken(req.Account, req.Password);
                        res.Message = "Login Success";
                        res.Token = token;
                        response.StatusCode = 200;
                        break;
                    case "create":
                        Account account = CreateAccount(req.Account, $"{req.Account}@dd.on", req.Password);
                        res.Message = "Account created";
                        response.StatusCode = 201;
                        break;
                }
            }
            catch (AccountRouteException ex)
            {
                res.Error = ex.Message;
                response.StatusCode = 401;
            }

            await response.WriteJsonAsync(res);
            return response;
        }

        private Account CreateAccount(string name, string mail, string password)
        {
            Account account = _database.SelectAccountByName(name);
            if (account != null)
            {
                Logger.Error($"{name} - CreateAccount: account already taken");
                throw new AccountRouteException("Account already exists.");
            }

            string hash = PasswordHash.CreateHash(password);
            account = _database.CreateAccount(name, mail, hash);
            return account;
        }

        private string CreateToken(string name, string password)
        {
            Account account = _database.SelectAccountByName(name);
            if (account == null)
            {
                Logger.Error($"{name} - CreateToken: account does not exist");
                throw new AccountRouteException("Account or password wrong.");
            }

            if (!PasswordHash.Verify(password, account.Hash))
            {
                Logger.Error($"{name} - CreateToken: wrong password provided");
                throw new AccountRouteException("Account or password wrong.");
            }

            if (account.State <= AccountStateType.Banned)
            {
                Logger.Error($"{name} - CreateToken: attempted login to banned account.");
                throw new AccountRouteException("This account has been banned.");
            }

            account.LoginToken = GameToken.GenerateLoginToken();
            account.LoginTokenCreated = DateTime.UtcNow;
            _database.UpdateAccount(account);
            return account.LoginToken;
        }
    }
}
