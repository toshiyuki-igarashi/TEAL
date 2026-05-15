import edu.mit.csail.sdg.alloy4.A4Reporter;
import edu.mit.csail.sdg.ast.Command;
import edu.mit.csail.sdg.ast.Module;
import edu.mit.csail.sdg.parser.CompUtil;
import edu.mit.csail.sdg.translator.A4Options;
import edu.mit.csail.sdg.translator.A4Solution;
import edu.mit.csail.sdg.translator.TranslateAlloyToKodkod;
import java.util.Collections;

public class AlloyCli {
    public static void main(String[] args) {

        // 引数が1つの場合は、Alloy公式のGUIモードとして起動する
        if (args.length == 1) {
            try {
                // Alloy公式のGUIメインクラスに、渡されたファイルパスをそのまま引き継ぐ
                edu.mit.csail.sdg.alloy4whole.SimpleGUI.main(new String[]{ args[0] });
            } catch (Exception e) {
                e.printStackTrace();
            }
            return;     // GUIを開いたら、後ろの検証ロジックには進まない
        }

        // ① 引数を3つ受け取る
        if (args.length < 3) {
            System.err.println("Usage: java -jar alloy-cli.jar <model.als> <goal_name> <output.xml>");
            System.exit(1);
        }

        String filename = args[0];
        String targetGoal = args[1];    // Rustから渡されるゴール名
        String xmlOutputPath = args[2]; // XMLの保存先

        A4Reporter reporter = new A4Reporter();

        try {
            Module world = CompUtil.parseEverything_fromFile(reporter, null, filename);
            A4Options options = new A4Options();

            for (Command command : world.getAllCommands()) {
                // ① 対象のゴールのみを実行する
                if (!command.label.equals(targetGoal)) {
                    continue; 
                }

                A4Solution ans = TranslateAlloyToKodkod.execute_command(reporter, world.getAllReachableSigs(), command, options);
                
                if (ans.satisfiable()) {
                    System.out.println("Counterexample found for " + command.label);
                    // NullPointerException回避の修正
                    ans.writeXML(xmlOutputPath, Collections.emptyList());
                } else {
                    System.out.println("No counterexample found for " + command.label);
                }
            }

            // ② 削除：反例があっても System.exit(1) はせず、正常終了(コード0)させる
            // if (failCount > 0) { System.exit(1); }

        } catch (Exception e) {
            System.err.println("Alloy Execution Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1); // 本当のパースエラーやメモリ不足の時だけ異常終了させる
        }
    }
}
