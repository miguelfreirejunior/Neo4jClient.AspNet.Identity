using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Neo4jClient.AspNet.Identity.Helpers;
using Newtonsoft.Json;

namespace Neo4jClient.AspNet.Identity
{
    public class LabeledEntity<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Gets or sets the primary key for this entity
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Optimistic concurrency flag
        /// </summary>
        public long TimeStamp { get; set; }

        /// <summary>
        /// Never serialize timestamp, currently the control must be manual
        /// </summary>
        /// <returns>false</returns>
        public bool ShouldSerializeTimeStamp() => false;

        /// <summary>
        /// A formatted string that represents this entity, ex: ":Entity:Nullable"
        /// </summary>
        public string Labels
        {
            get
            {
                var retorno = this.GetType().Labels();
                if (!string.IsNullOrWhiteSpace(retorno))
                {
                    return retorno;
                }

                throw new ArgumentException($"No labels defined for entity {this.GetType().Name}");
            }
        }
    }
}
