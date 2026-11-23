// SPDX-License-Identifier: Apache-2.0
// Encodes karyos#646's golden vectors with the reference SBE tool's
// generated Java codecs (sbe-all 1.42.0) and prints them as hex.
import org.agrona.concurrent.UnsafeBuffer;
import java.nio.ByteBuffer;

public final class Vectors {

    public static void main(final String[] args) {
        System.out.println("V1 " + hex(baseline()));
        System.out.println("V2 " + hex(extension()));
    }

    static String hex(final byte[] bytes) {
        final StringBuilder out = new StringBuilder();
        for (final byte b : bytes) {
            out.append(String.format("%02x", b & 0xff));
        }
        return out.toString();
    }

    static byte[] baseline() {
        final UnsafeBuffer buffer = new UnsafeBuffer(ByteBuffer.allocate(4096));
        final baseline.MessageHeaderEncoder header = new baseline.MessageHeaderEncoder();
        final baseline.CarEncoder car = new baseline.CarEncoder();
        car.wrapAndApplyHeader(buffer, 0, header)
            .serialNumber(1234)
            .modelYear(2013)
            .available(baseline.BooleanType.T)
            .code(baseline.Model.A)
            .vehicleCode("abcdef");
        for (int i = 0; i < 4; i++) {
            car.someNumbers(i, i + 1);
        }
        car.extras().clear().sportsPack(true).cruiseControl(true);
        car.engine().capacity(2000).numCylinders((short) 4).manufacturerCode("123")
            .efficiency((byte) 35).boosterEnabled(baseline.BooleanType.T)
            .booster().boostType(baseline.BoostType.NITROUS).horsePower((short) 200);
        final baseline.CarEncoder.FuelFiguresEncoder fuel = car.fuelFiguresCount(3);
        fuel.next().speed(30).mpg(35.9f).usageDescription("Urban Cycle");
        fuel.next().speed(55).mpg(49.0f).usageDescription("Combined Cycle");
        fuel.next().speed(75).mpg(40.0f).usageDescription("Highway Cycle");
        final baseline.CarEncoder.PerformanceFiguresEncoder perf = car.performanceFiguresCount(2);
        perf.next().octaneRating((short) 95).accelerationCount(3)
            .next().mph(30).seconds(4.0f)
            .next().mph(60).seconds(7.5f)
            .next().mph(100).seconds(12.2f);
        perf.next().octaneRating((short) 99).accelerationCount(3)
            .next().mph(30).seconds(3.8f)
            .next().mph(60).seconds(7.1f)
            .next().mph(100).seconds(11.8f);
        car.manufacturer("Honda").model("Civic VTi").activationCode("abcdef");
        return copy(buffer, header.encodedLength() + car.encodedLength());
    }

    static byte[] extension() {
        final UnsafeBuffer buffer = new UnsafeBuffer(ByteBuffer.allocate(4096));
        final extension.MessageHeaderEncoder header = new extension.MessageHeaderEncoder();
        final extension.CarEncoder car = new extension.CarEncoder();
        car.wrapAndApplyHeader(buffer, 0, header)
            .serialNumber(1234)
            .modelYear(2013)
            .available(extension.BooleanType.T)
            .code(extension.Model.A)
            .vehicleCode("abcdef");
        for (int i = 0; i < 4; i++) {
            car.someNumbers(i, i + 1);
        }
        car.extras().clear().sportsPack(true).cruiseControl(true);
        car.engine().capacity(2000).numCylinders((short) 4).manufacturerCode("123")
            .efficiency((byte) 35).boosterEnabled(extension.BooleanType.T)
            .booster().boostType(extension.BoostType.NITROUS).horsePower((short) 200);
        car.uuid(0, 7).uuid(1, 3).cupHolderCount((short) 5);
        final extension.CarEncoder.FuelFiguresEncoder fuel = car.fuelFiguresCount(3);
        fuel.next().speed(30).mpg(35.9f).usageDescription("Urban Cycle");
        fuel.next().speed(55).mpg(49.0f).usageDescription("Combined Cycle");
        fuel.next().speed(75).mpg(40.0f).usageDescription("Highway Cycle");
        final extension.CarEncoder.PerformanceFiguresEncoder perf = car.performanceFiguresCount(2);
        perf.next().octaneRating((short) 95).accelerationCount(3)
            .next().mph(30).seconds(4.0f)
            .next().mph(60).seconds(7.5f)
            .next().mph(100).seconds(12.2f);
        perf.next().octaneRating((short) 99).accelerationCount(3)
            .next().mph(30).seconds(3.8f)
            .next().mph(60).seconds(7.1f)
            .next().mph(100).seconds(11.8f);
        car.manufacturer("Honda").model("Civic VTi").activationCode("abcdef");
        return copy(buffer, header.encodedLength() + car.encodedLength());
    }

    static byte[] copy(final UnsafeBuffer buffer, final int length) {
        final byte[] out = new byte[length];
        buffer.getBytes(0, out);
        return out;
    }
}
