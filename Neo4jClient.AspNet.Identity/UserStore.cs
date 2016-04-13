namespace Neo4jClient.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Helpers;
    using Microsoft.AspNet.Identity;
    using Neo4jClient;
    using Neo4jClient.Cypher;

    public class UserStore<TUser> :
        IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserRoleStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IUserEmailStore<TUser>,
        IUserLockoutStore<TUser>,
        IUserTwoFactorStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IUserStore<TUser>
        where TUser : IdentityUser, new()
    {
        private bool _disposed;
        private readonly IGraphClient _graphClient;

        public UserStore(IGraphClient graphClient)
        {
            _graphClient = graphClient;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        #region Internal Classes for Serialization

        internal class FindUserResult<T>
            where T : IdentityUser, new()
        {
            public T User { private get; set; }
            public IEnumerable<UserLoginInfo> Logins { private get; set; }
            public IEnumerable<IdentityUserClaim> Claims { private get; set; }

            public T Combine()
            {
                var output = User;
                if (Logins != null)
                    output.Logins = this.Logins.ToList();
                if (Claims != null)
                    output.Claims = this.Claims.ToList();

                return output;
            }
        }

        #endregion Internal Classes for Serialization

        #region IUserLoginStore

        /// <inheritdoc />
        public async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(login, "login");

            await this._graphClient.Cypher
                .Create("(u:User { Id: id})-[:HAS_LOGIN]->(l:Login { login })")
                .WithParam("login", login)
                .WithParam("id", user.Id)
                .ExecuteWithoutResultsAsync();
        }

        /// <inheritdoc />
        public async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(loginProvider, "loginProvider");
            Check.IsNull(providerKey, "providerKey");

            await this._graphClient.Cypher
                .OptionalMatch("(u:User { Id: id})-[:HAS_LOGIN]->(l:Login)")
                .Where((UserLoginInfo l) => l.LoginProvider == loginProvider)
                .AndWhere((UserLoginInfo l) => l.ProviderKey == providerKey)
                .WithParam("id", user.Id)
                .Delete("l")
                .ExecuteWithoutResultsAsync();
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var results = await this._graphClient.Cypher
                .OptionalMatch("(u:User { Id: id})-[:HAS_LOGIN]->(l:Login)")
                .WithParam("id", user.Id)
                .Return<UserLoginInfo>("l")
                .ResultsAsync;

            return results.ToList();
        }

        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNullOrWhiteSpace(loginProvider, "loginProvider");
            Check.IsNullOrWhiteSpace(providerKey, "providerKey");

            providerKey = providerKey.ToLowerInvariant().Trim();

            var results = await _graphClient.Cypher
                .Match("(l:Login)<-[:HAS_LOGIN]-(u:User)")
                .Where((UserLoginInfo l) => l.ProviderKey == providerKey)
                .AndWhere((UserLoginInfo l) => l.LoginProvider == loginProvider)
                .OptionalMatch("(u)-[:HAS_CLAIM]->(c:Claim)")
                .Return((u, c, l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<UserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>()
                }).ResultsAsync;

            var findUserResult = results.SingleOrDefault();
            return findUserResult == null ? null : findUserResult.Combine();
        }

        public async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.Id);
        }

        public async Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.UserName);
        }

        public async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(userName, "userName");

            user.UserName = userName;
            await Task.FromResult(0);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.NormalizedUserName);
        }

        public async Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(normalizedName, "normalizedName");

            user.NormalizedUserName = normalizedName;
            await Task.FromResult(0);
        }

        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            if (string.IsNullOrWhiteSpace(user.Id))
            {
                user.Id = Guid.NewGuid().ToString();
            }

            var query = _graphClient.Cypher.Create("(u:User { user })")
                .WithParams(new { user });

            await query.ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var query = new CypherFluentQuery(_graphClient)
                .Match("(u:User { Id: userParam.Id })")
                .Set("u = {userParam}")
                .WithParam("userParam", user);
            ////.With("u").OptionalMatch("(u)-[cr:HAS_CLAIM]->(c:Claim)").Delete("c,cr")
            ////.With("u").OptionalMatch("(u)-[lr:HAS_LOGIN]->(l:Login)").Delete("l,lr")
            ////.With("u").OptionalMatch("(u)-[rl:IN_ROLE]->(r:Role)").Delete("rl");

            ////query = AddClaims(query, user.Claims);
            ////query = AddLogins(query, user.Logins);

            await query.ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            await _graphClient.Cypher
                .Match("(u:User)")
                .Where((TUser u) => u.Id == user.Id)
                .OptionalMatch("(u)-[lr:HAS_LOGIN]->(l)")
                .OptionalMatch("(u)-[cr:HAS_CLAIM]->(c)")
                .Delete("u,lr,cr,l,c")
                .ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(userId, "userId");

            var query = new CypherFluentQuery(_graphClient)
                .Match("(u:User)")
                .Where((TUser u) => u.Id == userId)
                .OptionalMatch("(u)-[lr:HAS_LOGIN]->(l:Login)")
                .OptionalMatch("(u)-[cr:HAS_CLAIM]->(c:Claim)")
                .Return((u, c, l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<UserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>(),
                });

            var user = (await query.ResultsAsync).SingleOrDefault();

            return user == null ? null : user.Combine();
        }

        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNullOrWhiteSpace(normalizedUserName, "normalizedUserName");

            var query = new CypherFluentQuery(_graphClient)
                .Match("(u:User)")
                .Where((TUser u) => u.NormalizedUserName == normalizedUserName)
                .OptionalMatch("(u)-[lr:HAS_LOGIN]->(l:Login})")
                .OptionalMatch("(u)-[cr:HAS_CLAIM]->(c:Claim)")
                .Return((u, c, l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<UserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>(),
                });

            var results = await query.ResultsAsync;
            var findUserResult = results.SingleOrDefault();
            return findUserResult == null ? null : findUserResult.Combine();
        }

        public void Dispose()
        {
            _disposed = true;
        }

        #endregion

        #region IUserClaimStore


        private static ICypherFluentQuery AddClaims(ICypherFluentQuery query, IList<IdentityUserClaim> claims)
        {
            if (claims == null || claims.Count == 0)
                return query;

            for (int i = 0; i < claims.Count; i++)
            {
                var claimName = string.Format("claim{0}", i);
                var claimParam = claims[i];
                query = query.With("u")
                    .Create("(u)-[:HAS_CLAIM]->(c" + i + ":claim {" + claimName + "})")
                    .WithParam(claimName, claimParam);
            }
            return query;
        }

        public async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var results = await
                this._graphClient
                .Cypher
                .OptionalMatch("(u:User { Id: id})-[:HAS_CLAIM]->(c:claim)")
                .WithParam("id", user.Id)
                .Return<Claim>("c")
                .ResultsAsync;

            return results.ToList();
        }

        public async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNullOrEmpty(claims, "claims");
            Check.IsNull(user, "user");

            await this._graphClient
                .Cypher
                .WithParam("id", user.Id)
                .Unwind(claims, "claim")
                .Create("(u:User { Id: id})-[:HAS_CLAIM]->(c:claim { claim })")
                .ExecuteWithoutResultsAsync();
        }

        public async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(claim, "claim");
            Check.IsNull(newClaim, "newClaim");
            Check.IsNull(user, "user");

            await this._graphClient
                .Cypher
                .WithParam("id", user.Id)
                .WithParam("claim", claim)
                .WithParam("newClaim", newClaim)
                .Match("(u:User { Id: id })-[r:HAS_CLAIM]->(c:claim { claim })")
                .Delete("c")
                .Create("(u:User { Id: id })-[:HAS_CLAIM]->(c2:claim { newClaim })")
                .ExecuteWithoutResultsAsync();
        }

        public async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNullOrEmpty(claims, "claims");
            Check.IsNull(user, "user");

            await this._graphClient
                .Cypher
                .WithParam("id", user.Id)
                .Unwind(claims, "claim")
                .Match("(u:User { Id: id })-[r:HAS_CLAIM]->(c:claim { claim })")
                .Delete("c")
                .ExecuteWithoutResultsAsync();
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(claim, "claim");

            var results = await _graphClient.Cypher
                .Match("(u:User)-[:HAS_CLAIM]->(c:claim { claim })")
                .WithParam("claim", claim)
                .Return((u, c, l) => u).ResultsAsync;

            return results.Cast<TUser>().ToList();
        }

        #endregion

        #region IUserRoleStore

        public async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(roleName, "roleName");

            await this._graphClient.Cypher
                .Merge("(u:User { Id: id })-[:HAS_ROLE]->(r:Role { Name: roleName })")
                .WithParams(new { id = user.Id, roleName })
                .ExecuteWithoutResultsAsync();
        }

        public async Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(roleName, "roleName");

            await this._graphClient.Cypher
                .Match("(u:User { Id: id })-[h:HAS_ROLE]->(r:Role { Name: roleName })")
                .WithParams(new { id = user.Id, roleName })
                .Delete("h")
                .ExecuteWithoutResultsAsync();
        }

        public async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var results = await this._graphClient.Cypher
                .Match("(u:User { Id: id })-[:HAS_ROLE]->(r:Role)")
                .WithParams(new { id = user.Id })
                .Return<string>("r.Name")
                .ResultsAsync;

            return results.ToList();
        }

        public async Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(roleName, "roleName");

            var results = await this._graphClient.Cypher
                .Match("(u:User { Id: id })-[h:HAS_ROLE]->(r:Role { Name: roleName })")
                .WithParams(new { id = user.Id, roleName })
                .Return<string>("u.Id")
                .ResultsAsync;

            return results.Any();
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(roleName, "roleName");

            var results = await this._graphClient.Cypher
                .Match("(u:User)-[h:HAS_ROLE]->(r:Role { Name: roleName })")
                .WithParams(new { roleName })
                .Return<TUser>("u")
                .ResultsAsync;

            return results.ToList();
        }

        #endregion

        #region IUserPasswordStore

        public async Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.PasswordHash = passwordHash;
            await Task.FromResult(0);
        }

        public async Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.PasswordHash);
        }

        public async Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await Task.FromResult(user.PasswordHash != null);
        }

        #endregion

        #region IUserSecurityStampStore

        public async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.SecurityStamp = stamp;
            await Task.FromResult(0);
        }

        public async Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.SecurityStamp);
        }

        #endregion

        #region IUserEmailStore

        public async Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.Email = email;
            await Task.FromResult(0);
        }

        public async Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.Email);
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.EmailConfirmed);
        }

        public async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.EmailConfirmed = confirmed;
            await Task.FromResult(0);
        }

        public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var query = await this._graphClient.Cypher
                .Match("(u:User)")
                .Where((TUser u) => u.NormalizedEmail == normalizedEmail)
                .Return(u => u.As<TUser>())
                .ResultsAsync;

            return query.SingleOrDefault();
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.NormalizedEmail = normalizedEmail;
            return Task.FromResult(0);
        }

        #endregion

        #region IUserLockoutStore

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.LockoutEnd);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.LockoutEnd = lockoutEnd;
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        #endregion

        #region IUserTwoFactorStore

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.TwoFactorEnabled);
        }

        #endregion

        #region IUserPhoneNumberStore

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
        }

        #endregion
    }
}