import io.github.nitanmarcel.jdex.ui.SyntaxThemes;
import org.fife.ui.rsyntaxtextarea.TokenTypes;
import java.awt.Color;
public class IC {
  static String hex(Color c){ return String.format("#%06X", c.getRGB()&0xFFFFFF); }
  static Color classColor(String base){
    SyntaxThemes.INSTANCE.setBaseId(base);
    SyntaxThemes.INSTANCE.applyAll(); // invalidates cache
    return SyntaxThemes.INSTANCE.iconColor(TokenTypes.DATA_TYPE, new Color(0x59A869));
  }
  public static void main(String[] a){
    Color fallback = new Color(0x59A869);
    Color dark = classColor("dark");
    Color mono = classColor("monokai");
    Color light = classColor("default");
    System.out.println("class-icon color  dark="+hex(dark)+"  monokai="+hex(mono)+"  light="+hex(light));
    System.out.println("theme-derived (differ across themes & not fallback): " +
      (!dark.equals(mono) && !dark.equals(fallback)));
    SyntaxThemes.INSTANCE.setBaseId("auto"); SyntaxThemes.INSTANCE.applyAll();
  }
}
