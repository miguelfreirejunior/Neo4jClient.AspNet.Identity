using System;
using System.Linq;
using System.Reflection;

namespace Neo4jClient.AspNet.Identity.Helpers
{
    [System.AttributeUsage(AttributeTargets.Class, Inherited = true, AllowMultiple = true)]
    sealed class Neo4jLabelAttribute : Attribute
    {
        /// <summary>
        /// Auxiliar method to access the Neo4j Labels per class
        /// </summary>
        /// <typeparam name="T">Class to recover labels</typeparam>
        /// <returns>Labels</returns>
        public static string LabelsFor<T, TKey>()
            where TKey : IEquatable<TKey>
            where T : LabeledEntity<TKey>, new()
        {
            var labels = typeof(T).GetCustomAttributes(typeof(Neo4jLabelAttribute), true).Cast<Neo4jLabelAttribute>();

            return string.Join(":", labels.Select(l => l.Label));
        }

        readonly string label;

        public Neo4jLabelAttribute(string label)
        {
            this.label = label;
        }

        public string Label
        {
            get { return label; }
        }
    }
}
