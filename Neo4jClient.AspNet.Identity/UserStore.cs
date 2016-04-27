namespace Neo4jClient.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Helpers;
    using Microsoft.AspNet.Identity;
    using Neo4jClient;
    using Neo4jClient.Cypher;

    /// <summary>
    /// Creates a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    public class UserStore<TUser, TRole> : UserStore<TUser, TRole, string>
        where TUser : IdentityUser<string>, new()
        where TRole : IdentityRole<string>, new()
    {
        public UserStore(IGraphClient graphClient, IdentityErrorDescriber describer = null) : base(graphClient, describer) { }
    }

    public class UserStore<TUser, TRole, TKey> :
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
        where TKey : IEquatable<TKey>
        where TRole : IdentityRole<TKey>
        where TUser : IdentityUser<TKey>, new()
    {
        private bool _disposed;
        private readonly IGraphClient _graphClient;

        public UserStore(IGraphClient graphClient, IdentityErrorDescriber describer = null)
        {
            _graphClient = graphClient;
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
        }

        /// <summary>
        /// Gets or sets the <see cref="IdentityErrorDescriber"/> for any error that occurred with the current operation.
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        #region IUserLoginStore

        /// <inheritdoc />
        public async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(login, "login");

            await this._graphClient.Cypher
                .Create($"(u:{user.Labels})-[:HAS_LOGIN]->(l)")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .AndWhere((IdentityLogin<TKey> l) => l.LoginProvider == login.LoginProvider)
                .AndWhere((IdentityLogin<TKey> l) => l.ProviderDisplayName == login.ProviderDisplayName)
                .AndWhere((IdentityLogin<TKey> l) => l.ProviderKey == login.ProviderKey)
                .ExecuteWithoutResultsAsync();
        }

        /// <inheritdoc />
        public async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(loginProvider, "loginProvider");
            Check.IsNull(providerKey, "providerKey");

            await this._graphClient.Cypher
                .OptionalMatch($"(u:{user.Labels})-[:HAS_LOGIN]->(l)")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .Where((IdentityLogin<TKey> l) => l.LoginProvider == loginProvider)
                .AndWhere((IdentityLogin<TKey> l) => l.ProviderKey == providerKey)
                .Delete("l")
                .ExecuteWithoutResultsAsync();
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var results = await this._graphClient.Cypher
                .OptionalMatch($"(u:{user.Labels})-[:HAS_LOGIN]->(l)")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .Return<IdentityLogin<TKey>>("l")
                .ResultsAsync;

            return results.Select(l => l.ToUserLoginInfo()).ToList();
        }

        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNullOrWhiteSpace(loginProvider, "loginProvider");
            Check.IsNullOrWhiteSpace(providerKey, "providerKey");

            providerKey = providerKey.ToLowerInvariant().Trim();

            var results = await _graphClient.Cypher
                .Match($"(l:{typeof(IdentityLogin).Labels()})<-[:HAS_LOGIN]-(u:{typeof(TUser).Labels()})")
                .Where((IdentityLogin<TKey> l) => l.ProviderKey == providerKey)
                .AndWhere((IdentityLogin<TKey> l) => l.LoginProvider == loginProvider)
                .OptionalMatch("(u)-[:HAS_CLAIM]->(c)")
                .OptionalMatch("(u)-[:HAS_ROLE]->(r)")
                .Return((u, c, l, r) =>
                    u.As<TUser>().Fill(
                        r.CollectAs<TRole>().Cast<IdentityRole<TKey>>().ToList(),
                        c.CollectAs<IdentityClaim<TKey>>().ToList(),
                        l.CollectAs<IdentityLogin<TKey>>().ToList())).ResultsAsync;

            return results.SingleOrDefault();
        }

        public async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(ConvertIdToString(user.Id));
        }

        public async Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.UserName);
        }

        public async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(userName, "userName");

            user.UserName = userName;
            await Task.FromResult(0);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.NormalizedUserName);
        }

        public async Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(normalizedName, "normalizedName");

            user.NormalizedUserName = normalizedName;
            await Task.FromResult(0);
        }

        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsIdNull<TUser, TKey>(user, "user");

            var query = _graphClient.Cypher.Create($"(u:{user.Labels} {{ user }})")
                .WithParams(new { user });

            await query.ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var results = await _graphClient.Cypher
                .WithParam("userParam", user)
                .Match($"(u:{user.Labels} {{ Id: userParam.Id }})")
                .Where((TUser u) => u.TimeStamp == user.TimeStamp)
                .Set("u = userParam")
                .Set("r.TimeStamp = timestamp()")
                .Return(u => u.As<TUser>().TimeStamp)
                .ResultsAsync;

            if (results.Any())
            {
                user.TimeStamp = results.First();
                return IdentityResult.Success;
            }
            else
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var results = await _graphClient.Cypher
                .Match($"(u:{user.Labels})")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .AndWhere((TUser u) => u.TimeStamp == user.TimeStamp)
                .OptionalMatch("(u)-[lr:HAS_LOGIN]->(l)")
                .OptionalMatch("(u)-[cr:HAS_CLAIM]->(c)")
                .OptionalMatch("(u)-[rr:HAS_CLAIM]->(r)")
                .Delete("u,lr,cr,l,c,rr")
                .Return<long>("count(u)")
                .ResultsAsync;

            if (results.All(r => r > 0))
            {
                return IdentityResult.Success;
            }

            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }

        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(userId, "userId");

            var results = await _graphClient.Cypher
                .Match($"(u:{typeof(TUser).Labels()})")
                .Where((TUser u) => u.Id.Equals(this.ConvertIdFromString(userId)))
                .OptionalMatch("(u)-[:HAS_LOGIN]->(l)")
                .OptionalMatch("(u)-[:HAS_CLAIM]->(c)")
                .OptionalMatch("(u)-[:HAS_ROLE]->(r)")
                .Return((u, c, l, r) => new
                {
                    User = u.As<TUser>(),
                    Roles = r.CollectAs<TRole>(),
                    Claims = c.CollectAs<IdentityClaim<TKey>>(),
                    Logins = l.CollectAs<IdentityLogin<TKey>>()
                })
                .ResultsAsync;

            var ret = results.SingleOrDefault();
            return ret.User.Fill(ret.Roles, ret.Claims, ret.Logins);
        }

        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNullOrWhiteSpace(normalizedUserName, "normalizedUserName");

            var results = await _graphClient.Cypher
                .Match($"(u:{typeof(TUser).Labels()})")
                .Where((TUser u) => u.NormalizedUserName == normalizedUserName)
                .OptionalMatch("(u)-[:HAS_LOGIN]->(l)")
                .OptionalMatch("(u)-[:HAS_CLAIM]->(c)")
                .OptionalMatch("(u)-[:HAS_ROLE]->(r)")
                .Return((u, c, l, r) =>
                    u.As<TUser>().Fill(
                        r.CollectAs<TRole>().Cast<IdentityRole<TKey>>().ToList(),
                        c.CollectAs<IdentityClaim<TKey>>().ToList(),
                        l.CollectAs<IdentityLogin<TKey>>().ToList()))
                .ResultsAsync;

            return results.SingleOrDefault();
        }

        /// <summary>
        /// Converts the provided <paramref name="id"/> to a strongly typed key object.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided <paramref name="id"/>.</returns>
        public virtual TKey ConvertIdFromString(string id)
        {
            if (id == null)
            {
                return default(TKey);
            }
            return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        }

        /// <summary>
        /// Converts the provided <paramref name="id"/> to its string representation.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An <see cref="string"/> representation of the provided <paramref name="id"/>.</returns>
        public virtual string ConvertIdToString(TKey id)
        {
            if (id.Equals(default(TKey)))
            {
                return null;
            }
            return id.ToString();
        }

        public void Dispose()
        {
            _disposed = true;
        }

        #endregion

        #region IUserClaimStore

        public async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var results = await
                this._graphClient
                .Cypher
                .OptionalMatch($"(u:{user.Labels})-[:HAS_CLAIM]->(c)")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .Return<IdentityClaim<TKey>>("c")
                .ResultsAsync;

            return results.Select(c => c.ToClaim()).ToList();
        }

        public async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNullOrEmpty(claims, "claims");
            Check.IsNull(user, "user");

            await this._graphClient
                .Cypher
                .WithParam("id", user.Id)
                .Unwind(claims.Select(c => new IdentityClaim<TKey>(c)), "claim")
                .Match($"(u:{user.Labels} {{ Id: id }})")
                .Create($"(u)-[:HAS_CLAIM]->(c:{typeof(IdentityClaim).Labels()} {{ claim }})")
                .ExecuteWithoutResultsAsync();
        }

        public async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(claim, "claim");
            Check.IsNull(newClaim, "newClaim");
            Check.IsNull(user, "user");

            var iNewClaim = new IdentityClaim<TKey>(newClaim);

            await this._graphClient
                .Cypher
                .WithParam("newClaim", iNewClaim)
                .Match($"(u:{user.Labels})-[r:HAS_CLAIM]->(c)")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .AndWhere((IdentityClaim<TKey> c) => c.ClaimType == claim.Type)
                .AndWhere((IdentityClaim<TKey> c) => c.ClaimValue == claim.Value)
                .Delete("c")
                .Create($"(u)-[:HAS_CLAIM]->(c2:{iNewClaim.Labels} {{ newClaim }})")
                .ExecuteWithoutResultsAsync();
        }

        public async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNullOrEmpty(claims, "claims");
            Check.IsNull(user, "user");

            await this._graphClient
                .Cypher
                .WithParam("id", user.Id)
                .Unwind(claims.Select(c => new { ClaimType = c.Type, ClaimValue = c.Value }), "claim")
                .Match($"(u:{user.Labels} {{ Id: id }})-[:HAS_CLAIM]->(c:{typeof(IdentityClaim).Labels()} {{ claim }})")
                .Delete("c")
                .ExecuteWithoutResultsAsync();
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(claim, "claim");

            var results = await _graphClient.Cypher
                .Match($"(u:{typeof(TUser).Labels()})-[:HAS_CLAIM]->(c:{typeof(IdentityClaim).Labels()})")
                .AndWhere((IdentityClaim<TKey> c) => c.ClaimType == claim.Type)
                .AndWhere((IdentityClaim<TKey> c) => c.ClaimValue == claim.Value)
                .OptionalMatch("(u)-[:HAS_ROLE]->(r)")
                .OptionalMatch("(u)-[:HAS_LOGIN]->(l)")
                .Return((u, c, l, r) => 
                    u.As<TUser>().Fill(
                        r.CollectAs<TRole>().Cast<IdentityRole<TKey>>().ToList(),
                        c.CollectAs<IdentityClaim<TKey>>().ToList(),
                        l.CollectAs<IdentityLogin<TKey>>().ToList())).ResultsAsync;

            return results.Cast<TUser>().ToList();
        }

        #endregion

        #region IUserRoleStore

        public async virtual Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(normalizedRoleName, "normalizedRoleName");

            await this._graphClient.Cypher
                .Match($"(u:{user.Labels})", $"(r:{typeof(TRole).Labels()})")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .AndWhere((TRole r) => r.NormalizedName == normalizedRoleName)
                .Create("(u)-[:HAS_ROLE]->(r)")
                .ExecuteWithoutResultsAsync();
        }

        public async Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(normalizedRoleName, "normalizedRoleName");

            await this._graphClient.Cypher
                .Match($"(u:{user.Labels})-[rr:HAS_ROLE]->(r)")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .AndWhere((TRole r) => r.NormalizedName == normalizedRoleName)
                .Delete("rr")
                .ExecuteWithoutResultsAsync();
        }

        public async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            var results = await this._graphClient.Cypher
                .Match($"(u:{user.Labels})-[:HAS_ROLE]->(r)")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .Return(r => r.As<TRole>().Name)
                .ResultsAsync;

            return results.ToList();
        }

        public async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");
            Check.IsNull(normalizedRoleName, "normalizedRoleName");

            var results = await this._graphClient.Cypher
                .Match($"(u:{user.Labels})-[:HAS_ROLE]->(r)")
                .Where((TUser u) => u.Id.Equals(user.Id))
                .AndWhere((TRole r) => r.NormalizedName == normalizedRoleName)
                .Return<int>("count(u)")
                .ResultsAsync;

            return results.Any();
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(normalizedRoleName, "normalizedRoleName");

            var results = await this._graphClient.Cypher
                .Match($"(u:{typeof(TUser).Labels()})-[:HAS_ROLE]->(r:{typeof(TRole).Labels()})")
                .Where((TRole r) => r.NormalizedName == normalizedRoleName)
                .Return<TUser>("u")
                .ResultsAsync;

            return results.ToList();
        }

        #endregion

        #region IUserPasswordStore

        public async Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.PasswordHash = passwordHash;
            await Task.FromResult(0);
        }

        public async Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.PasswordHash);
        }

        public async Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await Task.FromResult(user.PasswordHash != null);
        }

        #endregion

        #region IUserSecurityStampStore

        public async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.SecurityStamp = stamp;
            await Task.FromResult(0);
        }

        public async Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.SecurityStamp);
        }

        #endregion

        #region IUserEmailStore

        public async Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.Email = email;
            await Task.FromResult(0);
        }

        public async Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.Email);
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return await Task.FromResult(user.EmailConfirmed);
        }

        public async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.EmailConfirmed = confirmed;
            await Task.FromResult(0);
        }

        public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var query = await this._graphClient.Cypher
                .Match($"(u:{typeof(TUser).Labels()})")
                .Where((TUser u) => u.NormalizedEmail == normalizedEmail)
                .Return(u => u.As<TUser>())
                .ResultsAsync;

            return query.SingleOrDefault();
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.NormalizedEmail = normalizedEmail;
            return Task.FromResult(0);
        }

        #endregion

        #region IUserLockoutStore

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.LockoutEnd);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.LockoutEnd = lockoutEnd;
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        #endregion

        #region IUserTwoFactorStore

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.TwoFactorEnabled);
        }

        #endregion

        #region IUserPhoneNumberStore

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Check.IsNull(user, "user");

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
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