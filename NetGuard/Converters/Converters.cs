using System.Globalization;
using NetGuard.Models;

namespace NetGuard.Converters;

public class ThreatColorConverter : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c) =>
        (v is ThreatLevel lv ? lv : ThreatLevel.Unknown) switch
        {
            ThreatLevel.Critical => Color.FromArgb("#FF0040"),
            ThreatLevel.High     => Color.FromArgb("#FF4444"),
            ThreatLevel.Medium   => Color.FromArgb("#FF9500"),
            ThreatLevel.Low      => Color.FromArgb("#FFD60A"),
            ThreatLevel.Clean    => Color.FromArgb("#30D158"),
            _                    => Color.FromArgb("#636366")
        };
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotImplementedException();
}

public class ThreatBgConverter : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c) =>
        (v is ThreatLevel lv ? lv : ThreatLevel.Unknown) switch
        {
            ThreatLevel.Critical => Color.FromArgb("#2D0014"),
            ThreatLevel.High     => Color.FromArgb("#2D0A0A"),
            ThreatLevel.Medium   => Color.FromArgb("#2D1A00"),
            ThreatLevel.Low      => Color.FromArgb("#2D2500"),
            ThreatLevel.Clean    => Color.FromArgb("#0A1F10"),
            _                    => Color.FromArgb("#161B27")
        };
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotImplementedException();
}

public class IsNotEmptyConverter : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c)
        => v is string s && !string.IsNullOrEmpty(s);
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotImplementedException();
}

public class BoolToColorConverter : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c)
    {
        var parts = (p as string ?? "#30D158|#636366").Split('|');
        return Color.FromArgb(v is true ? parts[0] : parts[1]);
    }
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotImplementedException();
}

public class InvertBoolConverter : IValueConverter
{
    public object Convert(object? v, Type t, object? p, CultureInfo c) => v is not true;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => v is not true;
}
