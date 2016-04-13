using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Neo4jClient.AspNet.Identity
{
    public class LabeledEntity
    {
        private static IDictionary<Type, string> LABELS = new Dictionary<Type, string>();

        /// <summary>
        /// Auxiliar method to access the Neo4j Labels per class
        /// </summary>
        /// <typeparam name="T">Class to recover labels</typeparam>
        /// <returns>Labels</returns>
        public static string LabelsFor<T>() where T : LabeledEntity, new()
        {
            if (!LABELS.ContainsKey(typeof(T)))
            {
                LABELS.Add(typeof(T), new T().FormattedLabel);
            }

            return LABELS[typeof(T)];
        }


        /// <summary>
        /// Define the class labels for Neo4j
        /// </summary>
        public ICollection<string> Labels { get; } = new List<string>();

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
        public string FormattedLabel
        {
            get
            {
                if (this.Labels.Any())
                {
                    return $":{string.Join(":", this.Labels)}";
                }

                throw new ArgumentException($"No labels defined for entity {this.GetType().Name}");
            }
        }
    }
}
