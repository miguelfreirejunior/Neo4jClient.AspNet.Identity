using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Neo4jClient.AspNet.Identity.Helpers
{
    public static class CypherHelper
    {
        /// <summary>
        /// Recover labels for the type
        /// </summary>
        /// <param name="type">Type to look</param>
        /// <returns>Formatted string labels</returns>
        public static string Labels(this Type type)
        {
            var labels = type.GetTypeInfo().GetCustomAttributes(typeof(Neo4jLabelAttribute), true).Cast<Neo4jLabelAttribute>();

            return string.Join(":", labels.Select(l => l.Label));
        }
    }
}
