/** Test helpers: the progress verifiers with self-reported state ACCEPTED, for tests of the descent/binding rules (B16 made attested state the default). */
import * as P from '../progress';

export const verifyProgressStep = (g: P.Goal, c: string, s: P.ProgressStep, o: P.VerifyStepOptions = {}) => P.verifyProgressStep(g, c, s, { requireAttestedState: false, ...o });
export const verifyTrajectory = (g: P.Goal, c: string, s: readonly P.ProgressStep[], o: P.VerifyTrajectoryOptions = {}) => P.verifyTrajectory(g, c, s, { requireAttestedState: false, ...o });
export const verifySignedProgressStep = (g: P.Goal, c: string, s: P.SignedProgressStep, o: P.VerifySignedStepOptions) => P.verifySignedProgressStep(g, c, s, { requireAttestedState: false, ...o });
export const verifySignedTrajectory = (g: P.Goal, c: string, s: readonly P.SignedProgressStep[], o: P.VerifySignedTrajectoryOptions) => P.verifySignedTrajectory(g, c, s, { requireAttestedState: false, ...o });
