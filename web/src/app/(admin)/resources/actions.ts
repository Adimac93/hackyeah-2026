"use server";

import { revalidatePath } from "next/cache";

import { getSession, requireWriter } from "@/lib/auth";
import { canAccessConsole } from "@/lib/domain";
import { RESOURCES_BUCKET } from "@/lib/resources";

/** Signed URLs live this long: enough to open a preview, too short to share. */
const SIGNED_URL_SECONDS = 300;

/** Object keys we generate: no folders, no traversal. */
function validName(name: string): boolean {
  return /^[\w.-]{1,200}$/.test(name) && !name.startsWith(".");
}

/** A short-lived link to view (or, with `download`, save) one file. RLS decides access. */
export async function resourceUrl(
  name: string,
  download: boolean,
): Promise<{ url: string } | { error: string }> {
  const { supabase, member } = await getSession();
  if (member === null || !canAccessConsole(member.role)) {
    return { error: "You don't have access to resources." };
  }
  if (!validName(name)) {
    return { error: "Unknown file." };
  }
  const { data, error } = await supabase.storage
    .from(RESOURCES_BUCKET)
    .createSignedUrl(
      name,
      SIGNED_URL_SECONDS,
      download ? { download: true } : undefined,
    );
  if (error !== null) {
    return { error: "Couldn't open this file. It may have been deleted." };
  }
  return { url: data.signedUrl };
}

export async function deleteResource(
  name: string,
): Promise<{ error?: string }> {
  const session = await requireWriter();
  if (session.error) {
    return { error: session.error };
  }
  if (!validName(name)) {
    return { error: "Unknown file." };
  }
  const { data, error } = await session.supabase.storage
    .from(RESOURCES_BUCKET)
    .remove([name]);
  if (error !== null || data.length === 0) {
    return { error: "Couldn't delete the file." };
  }
  revalidatePath("/resources");
  return {};
}
