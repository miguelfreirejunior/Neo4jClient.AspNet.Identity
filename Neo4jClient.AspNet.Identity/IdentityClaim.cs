using System;
using System.Security.Claims;
using Neo4jClient.AspNet.Identity.Helpers;

namespace Neo4jClient.AspNet.Identity
{
    public class IdentityClaim : IdentityClaim<string>
    {
        public IdentityClaim() : base()
        {
            Id = Guid.NewGuid().ToString();
        }

        public IdentityClaim(Claim claim) : base(claim)
        {
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents a claim that a user possesses. 
    /// </summary>
    /// <typeparam name="TKey">The type used for the primary key for this user that possesses this claim.</typeparam>
    [Neo4jLabel("Claim")]
    public class IdentityClaim<TKey> : LabeledEntity<TKey> where TKey : IEquatable<TKey>
    {
        public IdentityClaim()
        {
        }

        public IdentityClaim(Claim claim) : this()
        {
            this.ClaimType = claim.Type;
            this.ClaimValue = claim.Value;
        }

        /// <summary>
        /// Gets or sets the claim type for this claim.
        /// </summary>
        public virtual string ClaimType { get; set; }

        /// <summary>
        /// Gets or sets the claim value for this claim.
        /// </summary>
        public virtual string ClaimValue { get; set; }

        public Claim ToClaim()
        {
            return new Claim(this.ClaimType, this.ClaimValue);
        }
    }
}