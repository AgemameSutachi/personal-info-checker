import com.healthmarketscience.jackcess.Column;
import com.healthmarketscience.jackcess.ColumnBuilder;
import com.healthmarketscience.jackcess.Cursor;
import com.healthmarketscience.jackcess.DataType;
import com.healthmarketscience.jackcess.Database;
import com.healthmarketscience.jackcess.DatabaseBuilder;
import com.healthmarketscience.jackcess.Table;
import com.healthmarketscience.jackcess.TableBuilder;
import com.healthmarketscience.jackcess.complex.Attachment;
import com.healthmarketscience.jackcess.complex.ComplexValueForeignKey;
import com.healthmarketscience.jackcess.complex.SingleValue;
import com.healthmarketscience.jackcess.complex.Version;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * 個人情報チェッカーの Access の対処・検査で、ACE（.accdb）を Jackcess（Apache License 2.0）で書き換える小さな補助。
 *
 * 標準入力から1行1命令（タブ区切り・文字列は Base64 の UTF-8）を読み、標準出力へ結果を1行ずつ返す。
 * 呼び出し側（pii_checker/remedy_access.py）が、表・行の番号（SELECT * と同じ「表の中の通し番号」）を指定する。
 * 表そのものの削除・列そのものの削除は Jackcess が持たないので、表は「全行の削除」、列は「全行の値を空に」で代える。
 *
 * 命令:
 *   open  path             … 開く（書き込み可）
 *   （検査用。元のファイルには何も書かない）
 *   openro path            … 読み取り専用で開く
 *   readall table max [digest] … 表の全行を順に流す。row\tord\tcell... を1行ずつ（ord は read と同じ 1 始まりの順番）、最後に end。
 *                            max は読む行数の上限（0 は無制限）。行を溜めずに出す。digest を付けると、バイナリは中身の SHA-256（"h"+16進）、
 *                            読めなかった値は "e"+例外の名前で出す（塗りつぶしの前後で中身を比べる指紋用）
 *   tables                 … table\tname の並び、end
 *   columns table          … col\tname\tkind\tsize の並び、end
 *   read table ords        … row\tord\tcell... の並び、end（cell は下の形式）
 *   delete table ords      … ok\tcount
 *   update table n         … 続く n 行（ord\tcolidx\tcell\tcolidx\tcell...）を書き込む → ok\tcount
 *   clearcols table cols   … 全行のその列を空にする → ok\trows
 *   emptytable table       … 全行を削除する → ok\trows
 *   close                  … 書き出して終わる → ok
 *   （試験の検体を作るための命令）
 *   create path            … 新しい .accdb（Access 2010 形式）を作って開く
 *   newtable table n       … 続く n 行（列名の Base64 + タブ + text・memo・long）の列を持つ表を作る
 *   insert table n         … 続く n 行（cell をタブで並べた行）を、表の末尾へ足す
 * cell: "-"=空 / "s"+Base64=文字列 / "i"+数字 / "f"+数 / "b1"・"b0" / "d"+日時 / "x"=バイナリなど値を渡さないもの
 */
public class AccessRewrite {
    private static Database db;
    private static final PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String unb64(String s) {
        return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
    }

    private static String kindOf(DataType t) {
        switch (t) {
            case TEXT:
                return "text";
            case MEMO:
                return "memo";
            case BYTE:
            case INT:
            case LONG:
            case BIG_INT:
                return "int";
            case FLOAT:
            case DOUBLE:
            case MONEY:
            case NUMERIC:
                return "float";
            case BOOLEAN:
                return "bool";
            case SHORT_DATE_TIME:
            case EXT_DATE_TIME:
                return "date";
            case BINARY:
            case OLE:
            case GUID:
                return "bin";
            default:
                return "other";
        }
    }

    private static String cell(Object v) {
        if (v == null) {
            return "-";
        }
        if (v instanceof String) {
            return "s" + b64((String) v);
        }
        if (v instanceof Byte || v instanceof Short || v instanceof Integer || v instanceof Long) {
            return "i" + v.toString();
        }
        if (v instanceof Boolean) {
            return ((Boolean) v) ? "b1" : "b0";
        }
        if (v instanceof Float || v instanceof Double || v instanceof BigDecimal) {
            return "f" + v.toString();
        }
        if (v instanceof java.time.temporal.Temporal || v instanceof java.util.Date) {
            return "d" + v.toString();
        }
        return "x";
    }

    /**
     * 中身の指紋を取るための値の書き出し。cell と同じで、バイナリ（OLE など）だけは中身の SHA-256 を出す。
     * 複合列（添付ファイル・複数の値・メモの版の履歴）の値は、行に入っているのが別の隠れた表への番号だけなので、
     * 番号ではなく、その番号が指す中身（添付ならファイル名・種類・ファイルの中身）を読んで SHA-256 にする
     * （番号だけだと、塗りつぶしで添付の中身を壊しても指紋が変わらない）。
     */
    private static String digestCell(Object v) throws Exception {
        if (v instanceof ComplexValueForeignKey) {
            return "c" + hex(complexDigest((ComplexValueForeignKey) v));
        }
        String c = cell(v);
        if (!c.equals("x")) {
            return c;
        }
        byte[] raw = v instanceof byte[] ? (byte[]) v : String.valueOf(v).getBytes(StandardCharsets.UTF_8);
        return "h" + hex(java.security.MessageDigest.getInstance("SHA-256").digest(raw));
    }

    private static byte[] complexDigest(ComplexValueForeignKey fk) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update((fk.getComplexType().name() + "\n").getBytes(StandardCharsets.UTF_8));
        switch (fk.getComplexType()) {
            case ATTACHMENT:
                for (Attachment a : fk.getAttachments()) {
                    md.update(("a\t" + a.getFileName() + "\t" + a.getFileType() + "\n").getBytes(StandardCharsets.UTF_8));
                    byte[] data = a.getFileData();
                    md.update(data == null ? new byte[0] : java.security.MessageDigest.getInstance("SHA-256").digest(data));
                }
                break;
            case MULTI_VALUE:
                for (SingleValue s : fk.getMultiValues()) {
                    md.update(("m\t" + digestCell(s.get()) + "\n").getBytes(StandardCharsets.UTF_8));
                }
                break;
            case VERSION_HISTORY:
                for (Version ver : fk.getVersions()) {
                    md.update(("v\t" + digestCell(ver.getValue()) + "\t" + ver.getModifiedDateObject() + "\n").getBytes(StandardCharsets.UTF_8));
                }
                break;
            default:
                md.update(("u\t" + fk.intValue() + "\n").getBytes(StandardCharsets.UTF_8));
        }
        return md.digest();
    }

    /**
     * いまの行の複合列（添付ファイル・複数の値・版の履歴）の中身を消す。Jackcess は行を消しても、隠れた表に入っている
     * 複合列の中身を消さないので、行を消す前・列を空にする前にこれを呼ぶ（呼ばないと、消した行の添付がファイルに残る）。
     */
    private static void deleteComplexValues(Cursor cur, Iterable<? extends Column> cols) throws Exception {
        for (Column c : cols) {
            if (c.getType() != DataType.COMPLEX_TYPE) {
                continue;
            }
            Object v = cur.getCurrentRowValue(c);
            if (v instanceof ComplexValueForeignKey) {
                ((ComplexValueForeignKey) v).deleteAllValues();
            }
        }
    }

    private static String hex(byte[] h) {
        StringBuilder sb = new StringBuilder();
        for (byte b : h) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static Object parseCell(Column col, String token) {
        if (token.equals("-")) {
            return null;
        }
        String body = token.substring(1);
        String text = token.charAt(0) == 's' ? unb64(body) : body;
        switch (col.getType()) {
            case TEXT:
            case MEMO:
                return text;
            case BYTE:
            case INT:
            case LONG:
            case BIG_INT:
                return Long.parseLong(text.trim());
            case FLOAT:
            case DOUBLE:
                return Double.parseDouble(text.trim());
            default:
                throw new IllegalArgumentException("この型の列（" + col.getType() + "）には書き込めません");
        }
    }

    private static Set<Integer> parseInts(String s) {
        Set<Integer> r = new TreeSet<>();
        if (s.isEmpty()) {
            return r;
        }
        for (String p : s.split(",")) {
            r.add(Integer.parseInt(p));
        }
        return r;
    }

    private static void ok(String extra) {
        out.println(extra == null ? "ok" : "ok\t" + extra);
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            String[] f = line.split("\t", -1);
            try {
                String cmd = f[0];
                if (cmd.equals("open")) {
                    db = new DatabaseBuilder(new File(unb64(f[1]))).setReadOnly(false).setAutoSync(false).open();
                    db.setEnforceForeignKeys(false);
                    ok(null);
                } else if (cmd.equals("openro")) {
                    db = new DatabaseBuilder(new File(unb64(f[1]))).setReadOnly(true).open();
                    ok(null);
                } else if (cmd.equals("readall")) {
                    Table t = db.getTable(unb64(f[1]));
                    long max = f.length > 2 && !f[2].isEmpty() ? Long.parseLong(f[2]) : 0;
                    boolean digest = f.length > 3 && f[3].equals("digest");
                    Cursor cur = t.getDefaultCursor();
                    cur.reset();
                    long ord = 0;
                    while ((max <= 0 || ord < max) && cur.moveToNextRow()) {
                        ord++;
                        StringBuilder sb = new StringBuilder("row\t" + ord);
                        for (Column c : t.getColumns()) {
                            Object v;
                            try {
                                v = cur.getCurrentRowValue(c);
                            } catch (Exception e) {
                                // 指紋では、読めなかったことを毎回同じ文字で表す（値ごとに変わる文字にすると、塗る前と後で食い違う）
                                sb.append('\t').append(digest ? "e" + e.getClass().getName() : cell(new Object()));
                                continue;
                            }
                            sb.append('\t').append(digest ? digestCell(v) : cell(v));
                        }
                        out.println(sb);
                    }
                    out.println("end");
                } else if (cmd.equals("create")) {
                    db = new DatabaseBuilder(new File(unb64(f[1]))).setFileFormat(Database.FileFormat.V2010).create();
                    db.setEnforceForeignKeys(false);
                    ok(null);
                } else if (cmd.equals("newtable")) {
                    TableBuilder tb = new TableBuilder(unb64(f[1]));
                    int ncols = Integer.parseInt(f[2]);
                    for (int i = 0; i < ncols; i++) {
                        String[] e = in.readLine().split("\t", -1);
                        DataType dt = e[1].equals("memo") ? DataType.MEMO : (e[1].equals("long") ? DataType.LONG : DataType.TEXT);
                        tb.addColumn(new ColumnBuilder(unb64(e[0]), dt));
                    }
                    tb.toTable(db);
                    ok(null);
                } else if (cmd.equals("insert")) {
                    Table t = db.getTable(unb64(f[1]));
                    int nrows = Integer.parseInt(f[2]);
                    List<? extends Column> cols = t.getColumns();
                    for (int i = 0; i < nrows; i++) {
                        String[] e = in.readLine().split("\t", -1);
                        Object[] values = new Object[cols.size()];
                        for (int k = 0; k < cols.size() && k < e.length; k++) {
                            values[k] = parseCell(cols.get(k), e[k]);
                        }
                        t.addRow(values);
                    }
                    ok(String.valueOf(nrows));
                } else if (cmd.equals("tables")) {
                    List<String> names = new ArrayList<>(db.getTableNames());
                    Collections.sort(names);
                    for (String n : names) {
                        if (db.isLinkedTable(db.getTable(n))) {
                            continue;
                        }
                        out.println("table\t" + b64(n));
                    }
                    out.println("end");
                } else if (cmd.equals("columns")) {
                    Table t = db.getTable(unb64(f[1]));
                    for (Column c : t.getColumns()) {
                        out.println("col\t" + b64(c.getName()) + "\t" + kindOf(c.getType()) + "\t" + c.getLengthInUnits());
                    }
                    out.println("end");
                } else if (cmd.equals("read")) {
                    Table t = db.getTable(unb64(f[1]));
                    Set<Integer> want = parseInts(f[2]);
                    int last = want.isEmpty() ? 0 : ((TreeSet<Integer>) want).last();
                    Cursor cur = t.getDefaultCursor();
                    cur.reset();
                    int ord = 0;
                    while (ord < last && cur.moveToNextRow()) {
                        ord++;
                        if (!want.contains(ord)) {
                            continue;
                        }
                        StringBuilder sb = new StringBuilder("row\t" + ord);
                        for (Column c : t.getColumns()) {
                            Object v;
                            try {
                                v = cur.getCurrentRowValue(c);
                            } catch (Exception e) {
                                v = new Object();
                            }
                            sb.append('\t').append(cell(v));
                        }
                        out.println(sb);
                    }
                    out.println("end");
                } else if (cmd.equals("count")) {
                    ok(String.valueOf(db.getTable(unb64(f[1])).getRowCount()));
                } else if (cmd.equals("delete")) {
                    Table t = db.getTable(unb64(f[1]));
                    Set<Integer> want = parseInts(f[2]);
                    int last = want.isEmpty() ? 0 : ((TreeSet<Integer>) want).last();
                    Cursor cur = t.getDefaultCursor();
                    cur.reset();
                    int ord = 0;
                    int n = 0;
                    while (ord < last && cur.moveToNextRow()) {
                        ord++;
                        if (want.contains(ord)) {
                            deleteComplexValues(cur, t.getColumns());
                            cur.deleteCurrentRow();
                            n++;
                        }
                    }
                    ok(String.valueOf(n));
                } else if (cmd.equals("update")) {
                    Table t = db.getTable(unb64(f[1]));
                    int count = Integer.parseInt(f[2]);
                    Map<Integer, String[]> edits = new HashMap<>();
                    int last = 0;
                    for (int i = 0; i < count; i++) {
                        String[] e = in.readLine().split("\t", -1);
                        int ord = Integer.parseInt(e[0]);
                        edits.put(ord, e);
                        last = Math.max(last, ord);
                    }
                    List<? extends Column> cols = t.getColumns();
                    Cursor cur = t.getDefaultCursor();
                    cur.reset();
                    int ord = 0;
                    int n = 0;
                    while (ord < last && cur.moveToNextRow()) {
                        ord++;
                        String[] e = edits.get(ord);
                        if (e == null) {
                            continue;
                        }
                        for (int k = 1; k + 1 < e.length; k += 2) {
                            Column c = cols.get(Integer.parseInt(e[k]));
                            cur.setCurrentRowValue(c, parseCell(c, e[k + 1]));
                        }
                        n++;
                    }
                    ok(String.valueOf(n));
                } else if (cmd.equals("clearcols")) {
                    Table t = db.getTable(unb64(f[1]));
                    Set<Integer> idxs = parseInts(f[2]);
                    List<? extends Column> cols = t.getColumns();
                    Cursor cur = t.getDefaultCursor();
                    cur.reset();
                    int n = 0;
                    while (cur.moveToNextRow()) {
                        for (int i : idxs) {
                            if (cols.get(i).getType() == DataType.COMPLEX_TYPE) {
                                deleteComplexValues(cur, Collections.singletonList(cols.get(i)));
                            } else {
                                cur.setCurrentRowValue(cols.get(i), null);
                            }
                        }
                        n++;
                    }
                    ok(String.valueOf(n));
                } else if (cmd.equals("emptytable")) {
                    Table t = db.getTable(unb64(f[1]));
                    Cursor cur = t.getDefaultCursor();
                    cur.reset();
                    int n = 0;
                    while (cur.moveToNextRow()) {
                        deleteComplexValues(cur, t.getColumns());
                        cur.deleteCurrentRow();
                        n++;
                    }
                    ok(String.valueOf(n));
                } else if (cmd.equals("close")) {
                    if (db != null) {
                        db.flush();
                        db.close();
                        db = null;
                    }
                    ok(null);
                    return;
                } else {
                    out.println("err\t" + b64("知らない命令: " + cmd));
                }
            } catch (Throwable e) {
                String msg = e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
                out.println("err\t" + b64(msg));
            }
        }
        if (db != null) {
            db.close();
        }
    }
}
