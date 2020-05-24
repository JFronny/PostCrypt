using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace SimpleTestApp
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            TestCalcium calc = new TestCalcium();
            Console.WriteLine(new string('.', 15) + $"{10 / 4f}, {Console.Out.Encoding}, {calc.Meem() && calc.Test2().Result}");
        }

        class TestCalcium
        {
            public bool Meem() => new Random().Next(15) > 7;

            public async Task<bool> Test2() => true;
        }
    }
}