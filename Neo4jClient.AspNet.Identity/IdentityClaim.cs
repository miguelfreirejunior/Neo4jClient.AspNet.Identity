// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Claims;

namespace Neo4jClient.AspNet.Identity
{
    public class IdentityClaim : IdentityClaim<string>
    {
    }

    /// <summary>
    /// Represents a claim that a user possesses. 
    /// </summary>
    /// <typeparam name="TKey">The type used for the primary key for this user that possesses this claim.</typeparam>
    public class IdentityClaim<TKey> : LabeledEntity where TKey : IEquatable<TKey>
    {
        public IdentityClaim()
        {
            this.Labels.Add("Claim");
        }

        /// <summary>
        /// Gets or sets the identifier for this user claim.
        /// </summary>
        public virtual int Id { get; set; }

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