namespace Neo4jClient.AspNet.Identity.Helpers
{
    using System;
    using System.Collections;
    using System.Linq;

    /// <summary>
    ///     Static helper class to throw a new <see cref="Exception" />.
    /// </summary>
    internal static class Check
    {
        /// <summary>Throws an <see cref="System.ArgumentException" /> if the <paramref name="obj" /> given is <c>null</c>.</summary>
        /// <typeparam name="T">Must be a class.</typeparam>
        /// <param name="obj">The object to check.</param>
        /// <param name="parameterName">The name of the parameter the <paramref name="obj" /> was in.</param>
        /// <exception cref="System.ArgumentException">Thrown if the <paramref name="obj" /> given is <c>null</c>.</exception>
        public static void IsNull<T>(T obj, string parameterName) where T : class
        {
            If(obj, parameterName, t => t == null, string.Format("{0} can't be null", parameterName));
        }

        /// <summary>Throws an <see cref="System.ArgumentException" /> if the <paramref name="obj" /> given is <c>Empty</c>.</summary>
        /// <typeparam name="T">Must be a <see cref="IEnumerable"/>.</typeparam>
        /// <param name="obj">The object to check.</param>
        /// <param name="parameterName">The name of the parameter the <paramref name="obj" /> was in.</param>
        /// <exception cref="System.ArgumentException">Thrown if the <paramref name="obj" /> given is <c>null</c>.</exception>
        public static void IsNullOrEmpty<T>(T obj, string parameterName) where T : class, IEnumerable
        {
            IsNull<T>(obj, parameterName);

            If(obj, parameterName, t => !t.Cast<object>().Any(), string.Format("{0} can't be empty", parameterName));
        }

        /// <summary>Throws an <see cref="System.ArgumentException" /> if the <paramref name="s" /> given is <c>null</c> or whitespace.</summary>
        /// <param name="s">The string to check.</param>
        /// <param name="parameterName">The name of the parameter the <paramref name="s" /> was in.</param>
        /// <exception cref="System.ArgumentException">Thrown if the <paramref name="s" /> given is <c>null</c> or whitespace.</exception>
        public static void IsNullOrWhiteSpace(string s, string parameterName)
        {
            If(s, parameterName, string.IsNullOrWhiteSpace, string.Format("{0} can't be null or whitespace", parameterName));
        }

        private static void If<T>(T obj, string parameterName, Func<T, bool> func, string message)
        {
            if (func(obj))
                throw new System.ArgumentException(message, parameterName);
        }
    }
}