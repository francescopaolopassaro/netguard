using System.Globalization;

namespace NetGuard.Converters;

/// <summary>Returns true when the string value is not null/empty.</summary>
public class IsNotEmptyConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is string s && !string.IsNullOrEmpty(s);

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Converts bool to one of two strings.
/// ConverterParameter="TrueString|FalseString"
/// </summary>
public class BoolToStringConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var parts   = (parameter as string ?? "Yes|No").Split('|');
        var trueStr = parts.Length > 0 ? parts[0] : "Yes";
        var falseStr= parts.Length > 1 ? parts[1] : "No";
        return value is true ? trueStr : falseStr;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>Maps ThreatLevel enum to a display color string.</summary>
public class ThreatLevelToColorConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is Models.ThreatLevel level)
            return level switch
            {
                Models.ThreatLevel.High    => "#E53E3E",
                Models.ThreatLevel.Medium  => "#D97706",
                Models.ThreatLevel.Low     => "#2B6CB0",
                Models.ThreatLevel.Clean   => "#38A169",
                _                          => "#718096"
            };
        return "#718096";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>Returns true if ThreatLevel >= Medium.</summary>
public class IsThreatConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is Models.ThreatLevel t && t >= Models.ThreatLevel.Medium;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>Converts bytes (long) to a human-readable size string.</summary>
public class BytesToHumanConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not long kb) return "-";
        double v = kb;
        return v switch
        {
            < 1024         => $"{v:N0} KB",
            < 1024 * 1024  => $"{v / 1024:N1} MB",
            _              => $"{v / (1024 * 1024):N1} GB"
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
