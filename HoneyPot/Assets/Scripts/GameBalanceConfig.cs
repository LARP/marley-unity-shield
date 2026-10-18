using UnityEngine;

namespace HoneyPot.Config
{
    /// <summary>
    /// ScriptableObject defining balance data and economic tuning parameters.
    /// Used to evaluate asset serialization visibility, field extraction, and data dumping.
    /// </summary>
    [CreateAssetMenu(fileName = "GameBalanceConfig", menuName = "HoneyPot/BalanceConfig")]
    public class GameBalanceConfig : ScriptableObject
    {
        [Header("Combat Scaling Factors")]
        [SerializeField] private float armorDecayRate = 0.05f;
        [SerializeField] private float criticalBaseChance = 0.125f;
        [SerializeField] private float globalDamageCap = 999999.0f;

        [Header("Economy Throttling")]
        [SerializeField] private int maxDailyCreditsCap = 500000;
        [SerializeField] private float premiumToStandardExchangeRate = 125.0f;
        [SerializeField] private bool antiArbitrageEnabled = true;

        [Header("Security Metadata")]
        [SerializeField] private string balanceTableSignature = "SHA256_SIG_BALANCE_908123";

        public float ArmorDecayRate => armorDecayRate;
        public float CriticalBaseChance => criticalBaseChance;
        public float GlobalDamageCap => globalDamageCap;
        public int MaxDailyCreditsCap => maxDailyCreditsCap;
        public float PremiumToStandardExchangeRate => premiumToStandardExchangeRate;
        public bool AntiArbitrageEnabled => antiArbitrageEnabled;
        public string BalanceTableSignature => balanceTableSignature;
    }
}
