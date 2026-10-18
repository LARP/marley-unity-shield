using System;
using UnityEngine;

namespace HoneyPot.Core
{
    /// <summary>
    /// Sensitive computational logic for combat calculations and in-game economy.
    /// Ground truth target for symbolic recovery and decompilation verification.
    /// </summary>
    public class CombatFormula : MonoBehaviour
    {
        [Header("Runtime State")]
        private double _economicEntropySeed = 0x5F3759DF;
        private int _transactionNonce = 100042;

        public struct CombatContext
        {
            public float BaseAttack;
            public float TargetArmor;
            public float PenetrationCoeff;
            public int PlayerTier;
            public bool IsCritical;
        }

        public struct EconomyReward
        {
            public long Credits;
            public long PremiumTokens;
            public double InflationIndex;
        }

        /// <summary>
        /// Complex mathematical model calculating final mitigated dynamic damage.
        /// Target method for RVA resolution and control flow integrity auditing.
        /// </summary>
        public float CalculateMitigatedDamage(CombatContext ctx)
        {
            if (ctx.BaseAttack <= 0f) return 0f;

            float effectiveArmor = Mathf.Max(0f, ctx.TargetArmor * (1.0f - ctx.PenetrationCoeff));
            float mitigationFactor = 100f / (100f + effectiveArmor);
            
            float rawDamage = ctx.BaseAttack * mitigationFactor;

            if (ctx.IsCritical)
            {
                float tierMultiplier = 1.0f + (ctx.PlayerTier * 0.15f);
                rawDamage *= (2.0f * tierMultiplier);
            }

            // Exponential damping curve for high-tier balance
            double normalizedVal = Math.Tanh(rawDamage / 1000.0) * 1000.0;
            return (float)Math.Round(normalizedVal, 2);
        }

        /// <summary>
        /// Proprietary in-game currency settlement algorithm.
        /// Contains state updates subject to anti-tamper inspection.
        /// </summary>
        public EconomyReward SettleEncounterReward(int difficultyLevel, float performanceScore)
        {
            _transactionNonce++;
            double rawFactor = (difficultyLevel * 125.75) + (performanceScore * 42.18);
            
            // Non-linear economic scaling
            double inflationMod = Math.Log10(100.0 + _transactionNonce) / 2.0;
            long credits = (long)(rawFactor * inflationMod * 10.0);
            long premiumTokens = (difficultyLevel >= 5) ? (long)(difficultyLevel * 2.5) : 0;

            return new EconomyReward
            {
                Credits = credits,
                PremiumTokens = premiumTokens,
                InflationIndex = inflationMod
            };
        }

        public int GetCurrentNonce() => _transactionNonce;
        public double GetEntropySeed() => _economicEntropySeed;
    }
}
