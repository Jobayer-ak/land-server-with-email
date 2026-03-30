// src/controllers/land.controller.ts
import { Request, Response } from 'express';

// Conversion factors
const GONDA_PER_ANA = 20;
const KORA_PER_GONDA = 4;
const KRANTI_PER_KORA = 3;
const TIL_PER_KRANTI = 20;

interface LandAmount {
  ana: number;
  gonda: number;
  kora: number;
  kranti: number;
  til: number;
}

interface Owner {
  id: string;
  name: string;
  landAmount: LandAmount;
  linkedTo: string | null;
}

// Convert land to til
const convertToTil = (land: LandAmount): number => {
  return (
    land.ana *
      GONDA_PER_ANA *
      KORA_PER_GONDA *
      KRANTI_PER_KORA *
      TIL_PER_KRANTI +
    land.gonda * KORA_PER_GONDA * KRANTI_PER_KORA * TIL_PER_KRANTI +
    land.kora * KRANTI_PER_KORA * TIL_PER_KRANTI +
    land.kranti * TIL_PER_KRANTI +
    land.til
  );
};

// Convert til to land
const convertFromTil = (totalTil: number): LandAmount => {
  let remaining = totalTil;

  const ana = Math.floor(
    remaining /
      (GONDA_PER_ANA * KORA_PER_GONDA * KRANTI_PER_KORA * TIL_PER_KRANTI),
  );
  remaining =
    remaining %
    (GONDA_PER_ANA * KORA_PER_GONDA * KRANTI_PER_KORA * TIL_PER_KRANTI);

  const gonda = Math.floor(
    remaining / (KORA_PER_GONDA * KRANTI_PER_KORA * TIL_PER_KRANTI),
  );
  remaining = remaining % (KORA_PER_GONDA * KRANTI_PER_KORA * TIL_PER_KRANTI);

  const kora = Math.floor(remaining / (KRANTI_PER_KORA * TIL_PER_KRANTI));
  remaining = remaining % (KRANTI_PER_KORA * TIL_PER_KRANTI);

  const kranti = Math.floor(remaining / TIL_PER_KRANTI);
  const til = remaining % TIL_PER_KRANTI;

  return { ana, gonda, kora, kranti, til };
};

// Calculate totals
const calculateTotals = (owners: Owner[]): LandAmount => {
  let totalTil = 0;
  owners.forEach((owner) => {
    totalTil += convertToTil(owner.landAmount);
  });
  return convertFromTil(totalTil);
};

export class LandController {
  // ✅ Calculate distribution endpoint
  static async calculate(req: Request, res: Response) {
    try {
      const { totalDecimal, owners } = req.body;

      console.log('📊 Calculation request:', {
        totalDecimal,
        ownerCount: owners?.length,
      });

      // Validation
      if (!totalDecimal || totalDecimal <= 0) {
        return res.status(400).json({
          success: false,
          error: 'মোট জমির পরিমাণ সঠিকভাবে দিন',
        });
      }

      if (!owners || owners.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'কমপক্ষে একজন মালিক থাকতে হবে',
        });
      }

      // Check if any owner has land
      const hasLand = owners.some(
        (owner: Owner) =>
          owner.landAmount.ana > 0 ||
          owner.landAmount.gonda > 0 ||
          owner.landAmount.kora > 0 ||
          owner.landAmount.kranti > 0 ||
          owner.landAmount.til > 0,
      );

      if (!hasLand) {
        return res.status(400).json({
          success: false,
          error: 'কমপক্ষে একজন মালিকের জমির পরিমাণ নির্বাচন করুন',
        });
      }

      // Process linked owners
      const processedOwners = owners.map((owner: Owner) => {
        if (owner.linkedTo) {
          const linkedOwner = owners.find(
            (o: Owner) => o.id === owner.linkedTo,
          );
          if (linkedOwner) {
            return {
              ...owner,
              landAmount: { ...linkedOwner.landAmount },
            };
          }
        }
        return owner;
      });

      // Calculate total til from all owners
      let totalTilFromDocs = 0;
      const ownersWithTil = processedOwners.map((owner: Owner) => {
        const til = convertToTil(owner.landAmount);
        totalTilFromDocs += til;
        return { ...owner, tilValue: til };
      });

      if (totalTilFromDocs === 0) {
        return res.status(400).json({
          success: false,
          error: 'মোট জমির পরিমাণ ০ হতে পারে না',
        });
      }

      // Calculate distribution
      const calculatedOwners = ownersWithTil.map((owner: any) => {
        const shareValue = owner.tilValue / totalTilFromDocs;
        const percentage = shareValue * 100;
        const decimalValue = shareValue * totalDecimal;

        return {
          id: owner.id,
          name: owner.name,
          landAmount: owner.landAmount,
          shareValue,
          percentage,
          decimalValue,
        };
      });

      const totals = calculateTotals(processedOwners);
      const totalShareSum = calculatedOwners.reduce(
        (sum: number, owner: any) => sum + owner.shareValue,
        0,
      );

      console.log('✅ Calculation completed');

      res.json({
        success: true,
        data: {
          owners: calculatedOwners,
          totals,
          totalShareSum,
          totalDecimal,
        },
      });
    } catch (error: any) {
      console.error('❌ Calculation error:', error);
      res.status(500).json({
        success: false,
        error: error.message || 'গণনা করতে সমস্যা হয়েছে',
      });
    }
  }

  // ✅ Convert land endpoint
  static async convert(req: Request, res: Response) {
    try {
      const { land } = req.body;

      console.log('🔄 Conversion request:', land);

      if (!land) {
        return res.status(400).json({
          success: false,
          error: 'জমির পরিমাণ দিন',
        });
      }

      // Validate land object
      if (
        typeof land.ana !== 'number' ||
        typeof land.gonda !== 'number' ||
        typeof land.kora !== 'number' ||
        typeof land.kranti !== 'number' ||
        typeof land.til !== 'number'
      ) {
        return res.status(400).json({
          success: false,
          error: 'জমির পরিমাণ সঠিকভাবে দিন',
        });
      }

      const til = convertToTil(land);
      const fromTil = convertFromTil(til);

      console.log('✅ Conversion completed:', { til, fromTil });

      res.json({
        success: true,
        data: {
          til,
          land: fromTil,
        },
      });
    } catch (error: any) {
      console.error('❌ Conversion error:', error);
      res.status(500).json({
        success: false,
        error: error.message || 'রূপান্তর করতে সমস্যা হয়েছে',
      });
    }
  }
}
