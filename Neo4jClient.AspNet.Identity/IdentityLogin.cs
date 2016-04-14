// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNet.Identity;
using Neo4jClient.AspNet.Identity.Helpers;

namespace Neo4jClient.AspNet.Identity
{
    public class IdentityLogin : IdentityLogin<string>
    {
        public IdentityLogin() : base()
        {
            Id = Guid.NewGuid().ToString();
        }

        public IdentityLogin(UserLoginInfo login) : base(login)
        {
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
    /// Represents a login and its associated provider for a user.
    /// </summary>
    /// <typeparam name="TKey">The type of the primary key of the user associated with this login.</typeparam>
    [Neo4jLabel("Login")]
    public class IdentityLogin<TKey> : LabeledEntity<TKey> where TKey : IEquatable<TKey>
    {
        public IdentityLogin()
        {
        }

        public IdentityLogin(UserLoginInfo login) : this()
        {
            this.LoginProvider = login.LoginProvider;
            this.ProviderDisplayName = login.ProviderDisplayName;
            this.ProviderKey = login.ProviderKey;
        }

        /// <summary>
        /// Gets or sets the login provider for the login (e.g. facebook, google)
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        /// Gets or sets the unique provider identifier for this login.
        /// </summary>
        public virtual string ProviderKey { get; set; }

        /// <summary>
        /// Gets or sets the friendly name used in a UI for this login.
        /// </summary>
        public virtual string ProviderDisplayName { get; set; }

        internal UserLoginInfo ToUserLoginInfo()
        {
            return new UserLoginInfo(this.LoginProvider, this.ProviderKey, this.ProviderDisplayName);
        }
    }
}