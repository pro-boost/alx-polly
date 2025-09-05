"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from "next/cache";

/**
 * Creates a new poll with question and multiple choice options
 * Validates user authentication, input data, and stores poll in database
 * 
 * @param formData - Form data containing question and options array
 * @returns Promise<{error: string | null}> - Success/error response object
 */
export async function createPoll(formData: FormData) {
  const supabase = await createClient();

  // Extract and validate form data
  const question = formData.get("question") as string;
  const options = formData.getAll("options").filter(Boolean) as string[];

  // Validate required fields and minimum options
  if (!question || options.length < 2) {
    return { error: "Please provide a question and at least two options." };
  }

  // Verify user authentication before creating poll
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    return { error: userError.message };
  }
  if (!user) {
    return { error: "You must be logged in to create a poll." };
  }

  // Insert new poll into database
  const { error } = await supabase.from("polls").insert([
    {
      user_id: user.id,
      question,
      options,
    },
  ]);

  if (error) {
    return { error: error.message };
  }

  // Revalidate polls page cache to show new poll
  revalidatePath("/polls");
  return { error: null };
}

/**
 * Retrieves all polls created by the currently authenticated user
 * Used for displaying user's poll dashboard and management interface
 * 
 * @returns Promise<Poll[] | null> - Array of user's polls or null if error/not authenticated
 */
export async function getUserPolls() {
  const supabase = await createClient();
  
  // Get current authenticated user
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { polls: [], error: "Not authenticated" };

  // Fetch all polls created by the user, ordered by creation date
  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) return { polls: [], error: error.message };
  return { polls: data ?? [], error: null };
}

/**
 * Retrieves a specific poll by its unique identifier
 * Used for displaying poll details, voting interface, and editing
 * 
 * @param id - The unique poll identifier
 * @returns Promise<{poll: Poll | null, error: string | null}> - Poll data or error
 */
export async function getPollById(id: string) {
  const supabase = await createClient();
  
  // Fetch single poll by ID
  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("id", id)
    .single();

  if (error) return { poll: null, error: error.message };
  return { poll: data, error: null };
}

/**
 * Submits a vote for a specific poll option
 * Handles vote recording and prevents duplicate voting (if user is authenticated)
 * 
 * @param pollId - The unique poll identifier
 * @param optionIndex - The index of the selected option (0-based)
 * @returns Promise<{error: string | null}> - Success/error response object
 */
export async function submitVote(pollId: string, optionIndex: number) {
  const supabase = await createClient();
  
  // Get current user (optional for anonymous voting)
  const {
    data: { user },
  } = await supabase.auth.getUser();

  // Note: Currently allows anonymous voting
  // Uncomment below to require authentication:
  // if (!user) return { error: 'You must be logged in to vote.' };

  // Record the vote in the database
  const { error } = await supabase.from("votes").insert([
    {
      poll_id: pollId,
      user_id: user?.id ?? null, // Allow anonymous votes with null user_id
      option_index: optionIndex,
    },
  ]);

  if (error) return { error: error.message };
  return { error: null };
}

/**
 * Deletes a poll and all associated votes
 * Only allows deletion by the poll owner (enforced by RLS policies)
 * 
 * @param id - The unique poll identifier to delete
 * @returns Promise<{error: string | null}> - Success/error response object
 */
export async function deletePoll(id: string) {
  const supabase = await createClient();
  
  // Delete poll (RLS policies ensure only owner can delete)
  const { error } = await supabase.from("polls").delete().eq("id", id);
  if (error) return { error: error.message };
  
  // Revalidate polls page to reflect deletion
  revalidatePath("/polls");
  return { error: null };
}

/**
 * Updates an existing poll's question and options
 * Validates user ownership and input data before updating
 * 
 * @param pollId - The unique poll identifier to update
 * @param formData - Form data containing updated question and options
 * @returns Promise<{error: string | null}> - Success/error response object
 */
export async function updatePoll(pollId: string, formData: FormData) {
  const supabase = await createClient();

  // Extract and validate form data
  const question = formData.get("question") as string;
  const options = formData.getAll("options").filter(Boolean) as string[];

  // Validate required fields and minimum options
  if (!question || options.length < 2) {
    return { error: "Please provide a question and at least two options." };
  }

  // Verify user authentication before updating
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    return { error: userError.message };
  }
  if (!user) {
    return { error: "You must be logged in to update a poll." };
  }

  // Update poll only if user is the owner (security check)
  const { error } = await supabase
    .from("polls")
    .update({ question, options })
    .eq("id", pollId)
    .eq("user_id", user.id);

  if (error) {
    return { error: error.message };
  }

  // Revalidate polls page to reflect changes
  revalidatePath("/polls");
  return { error: null };
}
