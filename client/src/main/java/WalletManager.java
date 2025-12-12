import cz.muni.fi.crocs.rcard.client.CardManager;

public class WalletManager extends BaseApduManager {
    public WalletManager(CardManager cardManager) {
        super(cardManager);
    }

    public void printComingSoon() {
        System.out.println();
        System.out.println("--- WALLET OPERATIONS ---");
        System.out.println("Not yet implemented.");
    }
}
